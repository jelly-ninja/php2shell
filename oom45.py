#!/usr/bin/env python3
"""oom45: (a) phpbuild35 tiny-body sanity — is CGI POST parsing broken in the
container at all? probe php://input len + $_POST count + warnings;
(b) deep core forensics: what does module_registry's dtor/bucket hold?"""
import subprocess

NAMELEN = 3064


def docker(cid, cmd, timeout=590, inp=None):
    r = subprocess.run(["docker", "exec", cid, "sh", "-c", cmd],
                       input=inp, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("latin1")


def tiny():
    ps = []
    for i in range(5):
        ps.append(b'--BOUND\r\nContent-Disposition: form-data; name="k%d"\r\n\r\nval%d\r\n' % (i, i))
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


if __name__ == "__main__":
    print("=== [a] phpbuild35 tiny-body sanity ===", flush=True)
    docker("phpbuild35", "printf '<?php header(\"Content-Type: text/plain\"); echo \"INPUTLEN=\".strlen(file_get_contents(\"php://input\")).\"\\\\n\"; echo \"POSTCOUNT=\".count($_POST).\"\\\\n\"; print_r(array_keys($_POST));' > /tmp/t_probe.php")
    body = tiny()
    _, cat = docker("phpbuild35", "cat /tmp/t_probe.php")
    print("probe script:", cat.strip()[:120])
    docker("phpbuild35", "cat > /tmp/tiny.bin", inp=body, timeout=120)
    _, wc = docker("phpbuild35", "wc -c < /tmp/tiny.bin")
    print("body bytes on disk:", wc.strip(), "built:", len(body))
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "/usr/src/php-8.2.35/sapi/cgi/php-cgi -d memory_limit=64000000 "
           "-d post_max_size=4096M -d max_input_vars=100000 "
           "-d display_errors=1 -d log_errors=0 "
           "</tmp/tiny.bin >/tmp/o35.log 2>/tmp/e35.log; echo RC=$?") % len(body)
    rc, out = docker("phpbuild35", cmd)
    _, o = docker("phpbuild35", "cat /tmp/o35.log; echo ---E---; cat /tmp/e35.log")
    print("rc:", out.strip())
    print(o)

    print("=== [b] core forensics: module_registry bucket ===", flush=True)
    g = ("gdb -q -batch "
         "-ex 'frame 4' "
         "-ex 'p ht->nNumUsed' "
         "-ex 'p ht->nNumOfElements' "
         "-ex 'p ht->pDestructor' "
         "-ex 'info symbol ht->pDestructor' "
         "-ex 'p ht->arData' "
         "-ex 'x/8gx ht->arData' "
         "-ex 'frame 0' "
         "-ex 'x/4i $pc' "
         "-ex 'info registers rdi rsi rax' "
         "/usr/src/php-8.2.34/sapi/cgi/php-cgi /tmp/core 2>&1 | tail -40")
    _, bt = docker("phpbuild", g)
    print(bt)
