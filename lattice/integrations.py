"""Certificate, Cloudflare, RFC 8310 ALPN 'dot', self-signed bootstrap, and FRP infrastructure integrations."""
from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import hostname
from .store import atomic_write


class CloudflareDNS:
    def __init__(self, token: str):
        self.token = token

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        request = urllib.request.Request(
            "https://api.cloudflare.com/client/v4" + path,
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            raise ValueError(f"Cloudflare returned HTTP {exc.code}") from None
        except OSError:
            raise ValueError("Cloudflare API is unreachable") from None
        if not body.get("success"):
            raise ValueError("Cloudflare rejected the request")
        return body["result"]

    def zone_for(self, fqdn: str) -> str:
        labels = fqdn.split(".")
        for index in range(len(labels) - 1):
            zone_name = ".".join(labels[index:])
            result = self.request("GET", "/zones?" + urllib.parse.urlencode({"name": zone_name, "per_page": 1}))
            if result:
                return result[0]["id"]
        raise ValueError("No accessible Cloudflare zone matches the hostname")

    def sync(self, fqdn: str, target: str) -> dict[str, Any]:
        fqdn = hostname(fqdn)
        if not target:
            raise ValueError("Public target is required")
        try:
            address = ipaddress.ip_address(target)
            if not address.is_global:
                raise ValueError("Public target must be globally routable")
            kind = "A" if address.version == 4 else "AAAA"
            normalized = str(address)
        except ValueError as exc:
            if "globally routable" in str(exc):
                raise
            kind = "CNAME"
            normalized = hostname(target, "public target")
        if normalized == fqdn:
            raise ValueError("Public target cannot point to the Private DNS hostname itself")

        zone = self.zone_for(fqdn)
        base = f"/zones/{zone}/dns_records"
        records = self.request("GET", base + "?" + urllib.parse.urlencode({"name": fqdn, "per_page": 100}))
        addresses = [r for r in records if r.get("type") in ("A", "AAAA", "CNAME")]
        same = [r for r in addresses if r.get("type") == kind]
        conflicts = [r for r in addresses if r.get("type") != kind]
        if conflicts or len(same) > 1:
            raise ValueError("Conflicting Cloudflare A, AAAA or CNAME records must be removed first")
        payload = {
            "type": kind,
            "name": fqdn,
            "content": normalized,
            "ttl": 120,
            "proxied": False,
            "comment": "Managed by Lattice DNS",
        }
        result = self.request("PUT" if same else "POST", base + ("/" + same[0]["id"] if same else ""), payload)
        return {key: result.get(key) for key in ("id", "name", "type", "content", "proxied")}


class CertificateVault:
    def __init__(self, store, on_change=None):
        self.store = store
        self.on_change = on_change
        self.root = store.root / "tls"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.context: ssl.SSLContext | None = None
        self.details: dict[str, Any] = {"valid": False, "error": "No certificate installed"}
        self.load()

    @staticmethod
    def _matches(pattern: str, fqdn: str) -> bool:
        pattern = pattern.lower()
        if pattern == fqdn:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return fqdn.endswith(suffix) and fqdn.count(".") == pattern.count(".")
        return False

    def validate(self, cert_pem: bytes, key_pem: bytes, fqdn: str) -> dict[str, Any]:
        fqdn = hostname(fqdn)
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
        cert_pub = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if cert_pub != key_pub:
            raise ValueError("Certificate and private key do not match")

        before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=dt.timezone.utc))
        after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=dt.timezone.utc))
        now = dt.datetime.now(dt.timezone.utc)
        if now < before or now >= after:
            raise ValueError("Certificate is not currently valid")
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        if not any(self._matches(name.lower(), fqdn) for name in names):
            raise ValueError("Certificate SAN does not cover the Private DNS hostname")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        issuer_str = cert.issuer.rfc4514_string()
        subject_str = cert.subject.rfc4514_string()
        return {
            "valid": True,
            "hostname": fqdn,
            "names": names,
            "issuer": issuer_str,
            "self_signed": issuer_str == subject_str,
            "alpn": "dot",
            "not_before": before.timestamp(),
            "expires": after.timestamp(),
            "fingerprint": fingerprint,
            "error": "",
        }

    def _context(self, cert_path: Path, key_path: Path) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.options |= ssl.OP_NO_COMPRESSION
        if hasattr(ssl, "OP_SINGLE_ECDH_USE"):
            context.options |= ssl.OP_SINGLE_ECDH_USE
        try:
            # RFC 7858 / RFC 8310 ALPN identifier for DNS-over-TLS ("dot")
            context.set_alpn_protocols(["dot"])
        except (NotImplementedError, ssl.SSLError):
            pass
        context.load_cert_chain(cert_path, key_path)
        return context

    def activate(self, cert_pem: bytes, key_pem: bytes, fqdn: str) -> dict[str, Any]:
        with self.lock:
            details = self.validate(cert_pem, key_pem, fqdn)
            generation = self.root / f"generation-{time.time_ns()}"
            generation.mkdir(mode=0o700)
            cert_path = generation / "fullchain.pem"
            key_path = generation / "privkey.pem"
            atomic_write(cert_path, cert_pem)
            atomic_write(key_path, key_pem)
            atomic_write(generation / "hostname", fqdn)
            context = self._context(cert_path, key_path)
            atomic_write(self.root / "active", generation.name)
            self.context = context
            self.details = details
            generations = sorted(self.root.glob("generation-*"), key=lambda p: p.name, reverse=True)
            for old in generations[3:]:
                shutil.rmtree(old, ignore_errors=True)
        if self.on_change:
            self.on_change()
        return details

    def generate_self_signed(self, fqdn: str = "", days: int = 365) -> dict[str, Any]:
        """Generate and activate a SAN-matched X.509 certificate for immediate DoT testing or opportunistic mode."""
        target_fqdn = hostname(fqdn or self.store.config.get("hostname") or "dns.lattice.internal")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lattice DNS Control Plane"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_fqdn),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=max(1, min(days, 825))))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(target_fqdn)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return self.activate(cert_pem, key_pem, target_fqdn)

    def load(self) -> None:
        pointer = self.root / "active"
        if not pointer.exists():
            return
        try:
            name = pointer.read_text().strip()
            generation = self.root / name
            if generation.parent != self.root or not name.startswith("generation-"):
                raise ValueError("Invalid certificate pointer")
            fqdn = (generation / "hostname").read_text().strip()
            cert = (generation / "fullchain.pem").read_bytes()
            key = (generation / "privkey.pem").read_bytes()
            details = self.validate(cert, key, fqdn)
            self.context = self._context(generation / "fullchain.pem", generation / "privkey.pem")
            self.details = details
        except Exception:
            self.context = None
            self.details = {"valid": False, "error": "Saved certificate is unusable"}

    def status(self) -> dict[str, Any]:
        details = dict(self.details)
        if details.get("expires"):
            details["days_left"] = round((details["expires"] - time.time()) / 86400, 1)
            details["hostname_matches"] = details.get("hostname") == self.store.config.get("hostname")
        return details

    def issue(self, agree: bool = False) -> dict[str, Any]:
        cfg = self.store.config
        fqdn = cfg["hostname"]
        email = cfg["email"]
        token = self.store.secret("cloudflare")
        if not agree and not self.store.meta("acme_terms", False):
            raise ValueError("ACME subscriber agreement must be accepted")
        if not fqdn or not email or not token:
            raise ValueError("Hostname, email and Cloudflare token are required")
        self.store.set_meta("acme_terms", True)

        root = self.store.root / "acme"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        credentials = root / "cloudflare.ini"
        atomic_write(credentials, "dns_cloudflare_api_token = " + token + "\n")
        command = [
            "certbot",
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--keep-until-expiring",
            "--dns-cloudflare",
            "--dns-cloudflare-credentials",
            str(credentials),
            "--dns-cloudflare-propagation-seconds",
            "60",
            "--email",
            email,
            "-d",
            fqdn,
            "--cert-name",
            fqdn,
            "--config-dir",
            str(root / "config"),
            "--work-dir",
            str(root / "work"),
            "--logs-dir",
            str(root / "logs"),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=420)
            if result.returncode:
                log = (result.stdout + "\n" + result.stderr).lower()
                if "rate limit" in log or "too many" in log:
                    raise ValueError("ACME rate limit reached")
                if any(token in log for token in ("authentication", "zone_id", "permission", "6003", "6111")):
                    raise ValueError("Cloudflare token permissions are insufficient")
                raise ValueError("ACME issuance failed")
            live = root / "config" / "live" / fqdn
            return self.activate((live / "fullchain.pem").read_bytes(), (live / "privkey.pem").read_bytes(), fqdn)
        finally:
            credentials.unlink(missing_ok=True)

    def renew_if_needed(self) -> bool:
        status = self.status()
        if not status.get("valid") or status.get("days_left", 999) >= 25:
            return False
        self.issue(agree=True)
        return True


def render_frpc(cfg: dict[str, Any], token: str, local_port: int) -> str:
    frp = cfg["frp"]
    lines = [
        f"serverAddr = {json.dumps(frp['server'])}",
        f"serverPort = {frp['port']}",
        "loginFailExit = false",
        "transport.tls.enable = true",
        'log.level = "info"',
        "log.disablePrintColor = true",
    ]
    if frp["auth"] == "token":
        if not token:
            raise ValueError("FRP token authentication is selected but no token is saved")
        lines += ['auth.method = "token"', f"auth.token = {json.dumps(token)}"]
    lines += [
        "",
        "[[proxies]]",
        f"name = {json.dumps(frp['proxy_name'])}",
        'type = "tcp"',
        'localIP = "127.0.0.1"',
        f"localPort = {local_port}",
        f"remotePort = {frp['remote_port']}",
        'transport.proxyProtocolVersion = "v1"',
    ]
    return "\n".join(lines) + "\n"


class FRPSupervisor:
    def __init__(self, store, local_port: int = 8854):
        self.store = store
        self.local_port = local_port
        self.path = store.root / "frpc.toml"
        self.lock = threading.RLock()
        self.process: subprocess.Popen | None = None
        self.state = "disabled"
        self.error = ""
        self.logs = collections.deque(maxlen=80)
        self.started = 0.0

    def apply(self, cfg: dict[str, Any] | None = None) -> None:
        cfg = cfg or self.store.config
        with self.lock:
            if not cfg["frp"]["enabled"]:
                self.stop()
                self.state = "disabled"
                self.error = ""
                return
            text = render_frpc(cfg, self.store.secret("frp"), self.local_port)
            candidate = self.path.with_suffix(".candidate")
            atomic_write(candidate, text)
            frpc_bin = shutil.which("frpc", path="/usr/local/bin:/usr/bin:/bin:" + os.environ.get("PATH", "")) or "frpc"
            verify = subprocess.run([frpc_bin, "verify", "-c", str(candidate)], capture_output=True, text=True, timeout=10)
            candidate.unlink(missing_ok=True)
            if verify.returncode:
                raise ValueError("FRP configuration validation failed")
            self.stop()
            atomic_write(self.path, text)
            self.process = subprocess.Popen(
                [frpc_bin, "-c", str(self.path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.started = time.time()
            self.state = "connecting"
            self.error = ""
            process = self.process

            def consume() -> None:
                assert process.stdout is not None
                for raw in process.stdout:
                    line = raw.strip()
                    for secret in (self.store.secret("frp"), self.store.secret("cloudflare")):
                        if secret:
                            line = line.replace(secret, "[redacted]")
                    self.logs.append(line[-700:])
                    low = line.lower()
                    if self.process is not process:
                        continue
                    if "start proxy success" in low:
                        self.state = "online"
                        self.error = ""
                    elif "try to reconnect" in low or "connection closed" in low:
                        self.state = "connecting"
                    elif any(term in low for term in ("start error", "login to server failed", "connect to server error")):
                        self.state = "error"
                        self.error = line[-500:]
                if self.process is process and process.poll() not in (None, 0):
                    self.state = "error"
                    self.error = self.error or "FRP client exited unexpectedly"

            threading.Thread(target=consume, daemon=True, name="frpc-log").start()

    def stop(self) -> None:
        process = self.process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self.process = None

    def status(self) -> dict[str, Any]:
        process = self.process
        running = bool(process and process.poll() is None)
        return {
            "running": running,
            "state": self.state if running or self.state == "disabled" else "stopped",
            "error": self.error,
            "uptime": int(time.time() - self.started) if running else 0,
            "logs": list(self.logs),
        }
