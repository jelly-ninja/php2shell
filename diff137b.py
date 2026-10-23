#!/usr/bin/env python3
"""diff137b: fixed body diff + full core.137_r4m forensics."""
import re, sys, struct, inspect

LAB = "/Users/vlad/Projects/queue/php2shell-lab"
sys.path.insert(0, LAB)

SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
MAGIC = 0xC0DEBA5E
TAG = 830
HDR = b"\x01\x00\x00\x00\x16\x00\x00\x00"

def prefix_ns(path):
    src = open(path).read()
    i = src.index("\nprint(")
    ns = {"__name__": "prefix"}
    exec(compile(src[:i], path + ":prefix", "exec"), ns)
    return ns

print("=== body diff ===", flush=True)
n134 = prefix_ns(LAB + "/oom134.py")
n137 = prefix_ns(LAB + "/oom137.py")
b134 = None
for name in ("build_name_sea", "build_post", "build_body"):
    fn = n134.get(name)
    if callable(fn):
        try:
            b134 = fn()
            print("oom134 %s() -> %d bytes" % (name, len(b134)))
            break
        except TypeError as e:
            print("oom134 %s()%s" % (name, inspect.signature(fn)), "->", e)
b137 = n137["build_post"](T16)
print("oom137 build_post(T16) -> %d bytes" % len(b137))
if b134:
    d = len(b134) - len(b137)
    print("delta(134-137)=%d" % d)
    n = min(len(b134), len(b137))
    diffs = [i for i in range(n) if b134[i] != b137[i]]
    print("diff byte count=%d, first at %s" % (len(diffs), diffs[:5]))
    for i in diffs[:3]:
        print("  @%d\n    134=%r\n    137=%r" % (i, b134[i-16:i+16], b137[i-16:i+16]))

print("=== core forensics ===", flush=True)
data = open("/tmp/scan_core", "rb").read()
print("core %d bytes" % len(data))

# segment table
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    pt = struct.unpack_from("<I", data, off)[0]
    po, pv, pa, pf = struct.unpack_from("<QQQQ", data, off + 8)
    if pt == 1 and pf > 0x10000:
        segs.append((po, pv, pf))
        print("PT_LOAD off=0x%x vaddr=0x%x filesz=0x%x" % (po, pv, pf))

def vaddr_of(foff):
    for po, pv, pf in segs:
        if po <= foff < po + pf:
            return pv + (foff - po)
    return None

# 1. tag occurrences (u64 + u32)
m8 = struct.pack("<Q", MAGIC + TAG)
hits = []
j = data.find(m8)
while j >= 0 and len(hits) < 10:
    hits.append(j)
    j = data.find(m8, j + 1)
print("tag u64 hits: %s" % [hex(h) for h in hits])
for h in hits:
    print("  @0x%x vaddr=%s ctx=%s" % (h, vaddr_of(h) and hex(vaddr_of(h)),
          data[max(0,h-24):h+24].hex()))
m4 = m8[:4]
cnt4 = 0; j = data.find(m4)
first4 = []
while j >= 0 and cnt4 < 20000:
    if len(first4) < 8: first4.append(j)
    cnt4 += 1; j = data.find(m4, j + 1)
print("tag u32 count=%d first=%s" % (cnt4, [hex(x) for x in first4]))

# 2. T16 window + phase slices
def count(pat):
    c = 0; k = data.find(pat)
    while k >= 0:
        c += 1; k = data.find(pat, k + 1)
    return c
print("T16 windows=%d" % count(T16))
for p in range(16):
    c = count((T16 + T16)[p:p + 8])
    if c:
        print("  phase-%d slice: %d" % (p, c))

# 3. context of first phase-7 slice
ph7 = (T16 + T16)[7:15]
w = data.find(ph7)
print("first ph7 slice @0x%x vaddr=%s" % (w, vaddr_of(w) and hex(vaddr_of(w))))
if w >= 0:
    h = data.rfind(HDR, max(0, w - 65536), w)
    print("  nearest temp HDR back: %s dist=%s" % (hex(h) if h >= 0 else "NONE",
          str(w - h) if h >= 0 else "-"))
    if h >= 0:
        print("  HDR vaddr=%s ; D(slice - valbase)=%s" % (
            hex(vaddr_of(h)) if vaddr_of(h) else "?",
            (vaddr_of(w) - (vaddr_of(h) + 0x18)) if (vaddr_of(w) and vaddr_of(h)) else "?"))
    print("  pre64=%s" % data[w-64:w].hex())
    print("  slice=%s post24=%s" % (data[w:w+8].hex(), data[w+8:w+32].hex()))

# 4. registry idx census
maxi = -1; cnt = 0
for mo in re.finditer(rb"K{200}(\d{1,4})", data):
    v = int(mo.group(1))
    if v > maxi: maxi = v
    cnt += 1
print("K+idx census: %d hits max idx=%d" % (cnt, maxi))
print("=== done ===", flush=True)
