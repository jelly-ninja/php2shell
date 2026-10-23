#!/usr/bin/env python3
"""diff137: (1) byte-diff oom134 vs oom137 bodies, (2) forensics on core.137_r4m.

Both drivers exec their PREFIX (everything before main's first print), so no
container is touched. Then build both measure bodies with T16 and diff.

Core scan answers:
  - is tag u64 (0xC0DEBA5E+830) present anywhere?  (A=None mystery)
  - how many T16 16B windows / phase-7 slices?
  - context around the phase-7 slice: nearest temp HDR within 65536 back
  - registry-idx census (max idx = the real cut for THIS body)
"""
import re, sys, struct, inspect, mmap

LAB = "/Users/vlad/Projects/queue/php2shell-lab"
sys.path.insert(0, LAB)

SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
MAGIC = 0xC0DEBA5E
TAG = 830

def prefix_ns(path):
    src = open(path).read()
    i = src.index("\nprint(")          # main body starts at first col-0 print
    ns = {"__name__": "prefix"}
    exec(compile(src[:i], path + ":prefix", "exec"), ns)
    return ns

print("=== body diff ===", flush=True)
n134 = prefix_ns(LAB + "/oom134.py")
n137 = prefix_ns(LAB + "/oom137.py")

b134 = b137_ = None
for name, fn in n134.items():
    if callable(fn) and "build" in name and not name.startswith("name132"):
        try:
            sig = inspect.signature(fn)
            b134 = fn(T16)
            print("oom134 builder %s%s -> %d bytes" % (name, sig, len(b134)))
        except TypeError as e:
            print("oom134 builder %s signature mismatch: %s" % (name, e))
for name in ("build_post",):
    b137_ = n137[name](T16)
    print("oom137 build_post -> %d bytes" % len(b137_))

if b134 and b137_:
    d = len(b134) - len(b137_)
    print("len(134)=%d len(137)=%d delta=%d" % (len(b134), len(b137_), d))
    n = min(len(b134), len(b137_))
    diffs = [i for i in range(n) if b134[i] != b137_[i]]
    print("first diffs: %s (total %d)" % (diffs[:10], len(diffs)))
    for i in diffs[:3]:
        print("  @%d 134=%r 137=%r" % (i, b134[i-12:i+12], b137_[i-12:i+12]))
else:
    print("!! could not build one of the bodies")

print("=== core.137_r4m forensics ===", flush=True)
f = open("/tmp/scan_core", "rb")
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
print("core size %d" % len(mm))

# 1. tag search
m8 = struct.pack("<Q", MAGIC + TAG)
m4 = m8[:4]
c8 = mm.find(m8); cnt4 = 0
j = mm.find(m4)
while j >= 0 and cnt4 < 5:
    cnt4 += 1
    j = mm.find(m4, j + 1)
print("tag u64 %r at %s ; u32 count>=%d" % (m8.hex(), hex(c8) if c8 >= 0 else "ABSENT", cnt4))

# 2. T16 windows + phase-7 slices
ph7 = T16[7:15]
c_t16 = mm.count(T16)
c_ph7 = mm.count(ph7)
print("T16 windows=%d  phase7 slices=%d" % (c_t16, c_ph7))

# 3. context around first phase-7 slice
w = mm.find(ph7)
HDR = b"\x01\x00\x00\x00\x16\x00\x00\x00"
if w >= 0:
    lo = max(0, w - 96)
    seg = mm[lo:w + 40]
    print("first ph7 @%d" % w)
    print("  before: %s" % seg[:96].hex())
    h = mm.rfind(HDR, max(0, w - 65536), w)
    print("  nearest temp HDR within 64K back: %s (dist %s)"
          % (hex(h) if h >= 0 else "NONE", str(w - h) if h >= 0 else "-"))
    # is the slice inside a run of tile bytes? check 64B alignment pattern
    back = mm[max(0, w - 64):w]
    fwd = mm[w + 8:w + 40]
    print("  after: %s" % fwd.hex())

# 4. registry idx census (K-run + digits)
maxi = 0; cnt = 0
pat = re.compile(rb"K{200}(\d{1,4})")
for mo in pat.finditer(mm):
    v = int(mo.group(1))
    if v > maxi:
        maxi = v
    cnt += 1
print("K-run+idx census: %d hits, max idx=%d" % (cnt, maxi))

# 5. envelope sanity: 'v'*64 runs and tile byte density
vb = b"v" * 64
print("v*64 runs=%d" % mm.count(vb))
mm.close(); f.close()
print("=== done ===", flush=True)
