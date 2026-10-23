#!/usr/bin/env python3
"""oom135: core.134_B tail forensics — the NUL-after question.

Name-sea crash core (rdi = tile bytes). Tail = freed ~3088B name-temp chunks.
Question: in tail chunks, what follows the name's NUL terminator?
If ZERO bytes -> 6-byte pointer + implicit NUL + stale-zero = legal rdi=B.
"""
import mmap, re, struct, subprocess, sys

subprocess.run(["docker", "cp", "phpbuild:/tmp/core.134_B", "/tmp/scan134B"], capture_output=True)
print("copy rc=%d size=%d" % (subprocess.run(["test", "-s", "/tmp/scan134B"]).returncode == 0, 0), flush=True)

T16 = struct.pack("<Q", 0x51E2C0DE51E2C0DE) + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
NEEDLE = T16 * 4                      # 64B of tiles
RDI_Q = struct.pack("<Q", 0xE2C0DE51E2C0DF51)  # rdi from oom134 B round

f = open("/tmp/scan134B", "rb")
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
print("core size %d" % len(mm), flush=True)

e_phoff = struct.unpack_from("<Q", mm, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    pt = struct.unpack_from("<I", mm, off)[0]
    po, pv, pa, pf = struct.unpack_from("<QQQQ", mm, off + 8)
    if pt == 1 and pf > 0x10000:
        segs.append((pv, po, pf))
print("segs %d" % len(segs), flush=True)

def dump(tag, data, base):
    print("%s @0x%x:" % (tag, base), flush=True)
    for k in range(0, len(data), 32):
        row = data[k:k + 32]
        print("  +0x%03x %s |%s|" % (k, row.hex(), "".join(chr(c) if 32 <= c < 127 else "." for c in row)), flush=True)

# 1) rdi-source window: dump around every rdi-qword hit (first 3)
hits = 0
for pv, po, pf in segs:
    d = mm[po:po + pf]
    s = 0
    while hits < 3:
        j = d.find(RDI_Q, s)
        if j < 0:
            break
        lo = max(0, j - 160)
        dump("RDIWIN seg@0x%x" % pv, d[lo:j + 96], pv + lo)
        hits += 1
        s = j + 1
print("rdi-window hits shown: %d" % hits, flush=True)

# 2) tile-name temp chunks: runs containing >=4 needle repeats; after the
#    run: idx digits + '[x]' + NUL + stale. Check stale zero-ness.
RUN_MIN = 3000
stale_stats = {0: 0, 1: 0, 2: 0}
samples = 0
chunk_count = 0
for pv, po, pf in segs:
    d = mm[po:po + pf]
    s = 0
    while True:
        j = d.find(NEEDLE, s)
        if j < 0:
            break
        # extend run forward tile by tile
        e = j + len(NEEDLE)
        while d[e:e + 16] == T16:
            e += 16
        runlen = e - j
        if runlen >= RUN_MIN:
            chunk_count += 1
            tail = d[e:e + 48]
            # after tiles: idx digits, '[x]', NUL, stale...
            z = tail.find(b"\x00")
            if z >= 0 and samples < 8:
                dump("CHUNTAIL run=%d" % runlen, tail, pv + e)
                samples += 1
            if z >= 0:
                after = tail[z + 1:z + 3]
                nz = sum(1 for c in after if c == 0)
                stale_stats[nz] = stale_stats.get(nz, 0) + 1
        s = e if runlen >= RUN_MIN else j + 1
print("tile chunks >=%dB: %d" % (RUN_MIN, chunk_count), flush=True)
print("stale zero-count after NUL (0/1/2 of 2 bytes): %s" % stale_stats, flush=True)

# 3) K-chunk equivalents: stock K names' temps -> same question for K chunks
pat = re.compile(rb"K{2048,}\d{1,5}\[x\]\x00")
kstats = {0: 0, 1: 0, 2: 0}
kn = 0
for pv, po, pf in segs:
    for m in pat.finditer(mm[po:po + pf]):
        kn += 1
        e = m.end()
        after = mm[po + e: po + e + 2]
        nz = sum(1 for c in after if c == 0)
        kstats[nz] = kstats.get(nz, 0) + 1
print("K name chunks: %d stale-zero(0/1/2 of 2): %s" % (kn, kstats), flush=True)

mm.close(); f.close()
print("=== done ===", flush=True)
