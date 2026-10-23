#!/usr/bin/env python3
"""raw137: RAW bytes around the trip slice in core.137_r4m — settle the chunk
geometry once: dump 96B before/after slice, find chunk boundary, print hex."""
import struct

PH7 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)  # slice content = SIG8 phase 7 = bytes 7..15 of T16
f = open("/tmp/scan_core", "rb").read()
print("core size", len(f))

# find all phase-7 SIG8 occurrences
hits = []
i = f.find(PH7)
while i != -1:
    hits.append(i)
    i = f.find(PH7, i + 1)
print("PH7 hits:", len(hits))

def hexdump(b, base):
    for r in range(0, len(b), 16):
        row = b[r:r+16]
        print("%010x  %s  |%s|" % (base + r, " ".join("%02x" % c for c in row),
              "".join(chr(c) if 32 <= c < 127 else "." for c in row)))

# pick the first hit inside a big run of tiles (the real sea), skip isolated
for j in hits[:6]:
    ctx = f[max(0, j-96): j+96]
    tiles_before = f[max(0, j-64):j].count(b"\xde")
    if tiles_before < 32:
        continue
    print("\n=== slice @ file 0x%x ===" % j)
    hexdump(f[j-96:j+96], j-96)
    break

# chunk-boundary hunt: scan back from slice for a 16B-aligned plausible header
# (refcount u32 + type_info u32 typical: (01 00 00 00) + type byte 0x06/0x01)
j = None
for h in hits:
    if f[h-64:h].count(b"\xde") >= 32:
        j = h
        break
print("\nscan-back from 0x%x:" % j)
for back in range(8, 3200, 8):
    o = j - back
    w = f[o:o+8]
    rc, ti = struct.unpack_from("<II", w)
    if rc in (1, 2) and 0x30 <= ti <= 0x400:
        print("  cand hdr @ -%d (0x%x): rc=%d ti=0x%x | %s" %
              (back, o, rc, ti, " ".join("%02x" % c for c in w)))
