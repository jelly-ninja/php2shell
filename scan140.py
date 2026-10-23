#!/usr/bin/env python3
"""scan140: forensic scan of core.140b (paired-ring measure crash, rdi=K*8).

Questions, in order:
1. How many SIG8-phase ring windows exist in heap segments? (Do freed rings
   reach the tail at all?)
2. Where is the crash bucket (from oom137: 0x...3be0-style) relative to
   ring windows?
3. What chunk does the trip window sit in - dump bytes around rdi context.
4. Do 0xde-heavy regions exist (ring bodies) - how large, how many?
"""
import struct

CORE = "/tmp/core.140b"
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)

f = open(CORE, "rb").read()
print("core size:", len(f))

# --- load segments ---
e_phoff = struct.unpack_from("<Q", f, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", f, 0x36)
segs = []
for k in range(e_phnum):
    off = e_phoff + k * e_phentsize
    p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<IIQQQQQ", f, off)
    if p_type == 1 and p_filesz >= 0x100000:
        segs.append((p_vaddr, p_off, p_filesz))
print("big segments:", [(hex(v), hex(o), hex(s)) for v, o, s in segs])

def v2f(v):
    for base, off, sz in segs:
        if base <= v < base + sz:
            return off + (v - base)
    return None

# --- rdi/rip from gdb decode (authoritative): rdi=0x4b4b4b4b4b4b4b4b ---
rdi = 0x4B4B4B4B4B4B4B4B
rip = 0  # zend_array_destroy+539 (gdb-verified)
print("rdi=0x%x (gdb)" % rdi)

# --- count ring windows (SIG8 at 8 mod 16 + 0xde fill) in segments ---
ring_win = 0
tile_win = 0
k_windows = 0
for base, off, sz in segs:
    buf = f[off:off + sz]
    j = buf.find(SIG8)
    while j != -1:
        # candidate ring window: SIG8 at position that is 8 mod 16 within a 0xde field
        if j % 16 == 8:
            s = max(0, j - 8)
            ctx = buf[s:s + 24]
            if ctx[0:8] == b"\xde" * 8:
                ring_win += 1
        j = buf.find(SIG8, j + 1)
    # tile windows (T16 phase 0)
    j = buf.find(T16)
    while j != -1:
        tile_win += 1
        j = buf.find(T16, j + 1)
    # K windows
    kb = b"K" * 8
    j = buf.find(kb)
    while j != -1:
        k_windows += 1
        j = buf.find(kb, j + 1)
print("ring windows (SIG8@8mod16 + de-fill):", ring_win)
print("T16 tile windows:", tile_win)
print("K*8 windows:", k_windows)

# --- 0xde run census: runs >= 512 bytes of mostly-0xde ---
runs = []
for base, off, sz in segs:
    buf = f[off:off + sz]
    j = buf.find(b"\xde" * 64)
    while j != -1:
        s = j
        while s > 0 and buf[s - 1] == 0xde:
            s -= 1
        e = j + 64
        while e < len(buf) and buf[e] == 0xde:
            e += 1
        if e - s >= 512:
            runs.append((base + s, e - s))
        j = buf.find(b"\xde" * 64, e)
print("0xde runs >=512B:", len(runs), "total bytes:", sum(r[1] for r in runs))
for v, n in runs[:10]:
    print("  run at 0x%x len %d" % (v, n))

# --- context around rdi (find K region containing rdi - if mappable) ---
fo = v2f(rdi & ~0xFFF)
print("rdi page mapped in core:", fo is not None)
if fo is not None:
    page = f[fo:fo + 4096]
    print("rdi page first 64:", page[:64].hex())
