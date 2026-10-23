#!/usr/bin/env python3
"""scan140b: map the crash neighborhood of core.140b.

rbx=0x7f642b903b40 (walk position). Segment 0x7f642b800000+0x200000 contains it.
Questions:
1. Hexdump rbx-0x100..rbx+0x100 (bucket slots around the trip).
2. Walk forward from rbx: what's at +9 for each 0x20 step (triage trace)?
3. Dump 512B around the trip chunk and check: K-filled name-temp? ring remnant?
4. Find ALL SIG8 ring windows in that segment; print addresses + distance to rbx.
5. Zend-string header hunt: find len=0xbf4 headers near rbx (both K-temps and rings).
"""
import struct

CORE = "/tmp/core.140b"
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)

f = open(CORE, "rb").read()
e_phoff = struct.unpack_from("<Q", f, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", f, 0x36)
segs = []
for k in range(e_phnum):
    off = e_phoff + k * e_phentsize
    p = struct.unpack_from("<IIQQQQQ", f, off)
    if p[0] == 1 and p[5] >= 0x100000:
        segs.append((p[3], p[2], p[5]))

def v2f(v):
    for base, off, sz in segs:
        if base <= v < base + sz:
            return off + (v - base)
    return None

RBX = 0x7f642b903b40
fo = v2f(RBX)
print("rbx mapped:", fo is not None)

def hd(v, n, label):
    fo = v2f(v)
    if fo is None:
        print(label, "UNMAPPED 0x%x" % v)
        return
    d = f[fo:fo + n]
    print("--- %s (0x%x) ---" % (label, v))
    for i in range(0, n, 32):
        print("  +0x%04x: %s" % (i, d[i:i + 32].hex()))

hd(RBX - 0x80, 0x180, "rbx neighborhood")

# triage trace: +9 bytes at 0x20 steps forward from rbx
print("--- triage trace (+9 byte at each 0x20 step, 40 steps) ---")
fo = v2f(RBX)
nz = []
for s in range(40):
    b = f[fo + s * 0x20 + 9]
    if b:
        nz.append((s, RBX + s * 0x20, b))
print("nonzero +9 slots:", [(s, hex(a), hex(b)) for s, a, b in nz[:12]])

# SIG8 ring windows in the rbx segment
base, off, sz = next((b, o, s) for b, o, s in segs if b <= RBX < b + s)
buf = f[off:off + sz]
print("--- ring windows in rbx segment 0x%x+0x%x ---" % (base, sz))
wins = []
j = buf.find(SIG8)
while j != -1:
    if j % 16 == 8:
        wins.append(base + j)
    j = buf.find(SIG8, j + 1)
print("count:", len(wins))
for w in wins[:30]:
    print("  0x%x  (rbx%+d)" % (w, w - RBX))

# zend_string len 0xbf4 headers near rbx (ring/K-temp chunk headers)
print("--- len=0xbf4 headers within 64KB below rbx ---")
lb = struct.pack("<Q", 0xbf4)
found = 0
scan_lo = RBX - 0x10000
for v in range(scan_lo, RBX + 0x1000, 8):
    fo2 = v2f(v)
    if fo2 is None:
        continue
    if f[fo2:fo2 + 8] == lb:
        # candidate header at v-16: gc(u32,u32)+h(u64)+len; check type_info plausible
        fo3 = v2f(v - 16)
        ti = struct.unpack_from("<I", f, fo3 + 4)[0]
        val = v - 16 + 24  # zend_string val
        print("  hdr@0x%x type_info=0x%x val=0x%x (rbx%+d)" % (v - 16, ti, val, val - RBX))
        found += 1
        if found > 24:
            break
