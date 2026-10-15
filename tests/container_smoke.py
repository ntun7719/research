import http.cookiejar
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

BASE = os.environ.get("LATTICE_URL", "http://127.0.0.1:18080")
SETUP_CODE = os.environ["LATTICE_SETUP_CODE"]
PASSWORD = "integration-password-2468"


def request(opener, path, method="GET", body=None, csrf=""):
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(BASE + path, method=method, data=data, headers=headers)
    with opener.open(req, timeout=10) as response:
        return json.load(response)


def dns_query(name):
    labels = name.encode().split(b".")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    return struct.pack("!6H", 0xBEEF, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("TLS DNS connection closed")
        data.extend(chunk)
    return bytes(data)


def dot_query(port, cafile):
    context = ssl.create_default_context(cafile=str(cafile))
    packet = dns_query("ads.example")
    with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname="dns.test") as conn:
            conn.sendall(struct.pack("!H", len(packet)) + packet)
            size = struct.unpack("!H", recv_exact(conn, 2))[0]
            response = recv_exact(conn, size)
    assert response[:2] == packet[:2]
    assert response[3] & 15 == 3, response.hex()


def wait_health():
    for _ in range(60):
        try:
            with urllib.request.urlopen(BASE + "/healthz", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("Lattice health endpoint did not become ready")


wait_health()

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
setup = request(opener, "/api/setup", "POST", {"code": SETUP_CODE, "password": PASSWORD})
csrf = setup["csrf"]

config_payload = request(opener, "/api/config")
cfg = config_payload["config"]
cfg["hostname"] = "dns.test"
cfg["frp"].update({
    "enabled": True,
    "server": "lattice-frps",
    "port": 7000,
    "remote_port": 853,
    "auth": "none",
    "proxy_name": "lattice-dot-ci"
})
request(opener, "/api/config", "PUT", {"config": cfg, "secrets": {}}, csrf)

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    cert = root / "cert.pem"
    key = root / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-days", "1", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=dns.test", "-addext", "subjectAltName=DNS:dns.test"
        ],
        check=True,
        capture_output=True,
    )
    request(
        opener,
        "/api/tls/upload",
        "POST",
        {"certificate": cert.read_text(), "private_key": key.read_text()},
        csrf,
    )
    request(
        opener,
        "/api/rules",
        "POST",
        {"pattern": "ads.example", "kind": "exact", "action": "deny", "profile": "*", "value": ""},
        csrf,
    )

    dot_query(18853, cert)

    online = False
    for _ in range(30):
        status = request(opener, "/api/status")
        if status["frp"]["state"] == "online":
            online = True
            break
        time.sleep(1)
    assert online, request(opener, "/api/status")["frp"]
    dot_query(1853, cert)

trace = request(opener, "/api/diagnostics/resolve", "POST", {"name": "ads.example", "qtype": 1}, csrf)
assert trace["name"] == "ads.example"
assert trace["policy"]["action"] == "deny"
assert trace["resolver"]["skipped"] is True

status = request(opener, "/api/status")
assert status["resolver"]["running"]
assert status["dot"]["running"]
assert status["tls"]["valid"]
print("container smoke passed")
