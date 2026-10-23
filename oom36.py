#!/usr/bin/env python3
"""oom36: exclusive-bin kill — name 4200 -> key 4234B -> 8192-bin (2 pages),
a bin NO transient uses (tmps 3584-bin, FILLUNIT 4096-bin). Keys are the
only 8192-bin client: when no adjacent page-pair remains and no chunk can
be mapped (free<2MB), the failure lands INSIDE the post-commit window.
Detector: keycommit without keyok / RC 139. NAMELEN sweep around 4200 as
control.
usage: oom36.py [len_lo] [len_hi] [step]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))

if __name__ == "__main__":
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 4200
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 4200
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 500
    for namelen in range(lo, hi + 1, step):
        if decode(namelen, make_builder(namelen)):
            break
