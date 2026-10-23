#!/usr/bin/env python3
"""diff137c: compute D (slice offset inside name-temp) from core.137_r4m, oom135 way."""
import struct

SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
PH7 = (T16 + T16)[7:15]
HDR = b"\x01\x00\x00\x00\x16\x00\x00\x00"

data = open("/tmp/scan_core", "rb").read()
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    pt = struct.unpack_from("<I", data, off)[0]
    po, pv, pa, pf = struct.unpack_from("<QQQQ", data, off + 8)
    if pt == 1 and pf > 0x10000:
        segs.append((po, pv, pf))

def vaddr(foff):
    for po, pv, pf in segs:
        if po <= foff < po + pf:
            return pv + (foff - po)
    return None

# heap segs = the big anonymous ones (vaddr 0x7f543c000000 range)
found = 0
for po, pv, pf in segs:
    if pv < 0x7f543c000000 or pv > 0x7f54400000000:
        continue
    if pf < 0x100000:
        continue
    start = po
    j = data.find(PH7, start, po + pf)
    n = 0
    while j >= 0 and found < 6:
        va = vaddr(j)
        h = data.rfind(HDR, max(start, j - 65536), j)
        hva = vaddr(h) if h >= 0 else None
        if h >= 0 and hva is not None:
            D = va - (hva + 0x18)
            pre = data[j-16:j]
            print("ph7 slice foff=0x%x vaddr=0x%x | HDR foff=0x%x vaddr=0x%x dist=%d D=%d pre16=%s"
                  % (j, va, h, hva, j - h, D, pre.hex()))
            found += 1
        n += 1
        if n > 200000:
            break
        j = data.find(PH7, j + 1, po + pf)
    if found >= 6:
        break
print("=== done (found %d) ===" % found)
