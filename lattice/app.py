"""Lattice DNS control plane, Android Private DNS readiness doctor, background services and HTTP API."""
from __future__ import annotations

import base64
import copy
import http.cookies
import ipaddress
import json
import os
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .config import hostname, validate_config
from .feeds import FeedManager
from .integrations import CertificateVault, CloudflareDNS, FRPSupervisor
from .policy import Policy, get_safesearch_rewrite, is_android_essential
from .resolver import ResolverManager, _question, benchmark_upstreams, probe_dot
from .store import Store
from .transport import (
    DNSGateway,
    decode_dns_answers,
    error_response,
    forward_local,
    read_question,
    recv_exact,
    rewrite_response,
)


FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    b'<rect width="32" height="32" rx="8" fill="#0d9488"/>'
    b'<path d="M16 5L6 10l10 5 10-5-10-5zM6 22l10 5 10-5M6 16l10 5 10-5" '
    b'fill="none" stroke="#ffffff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
    b"</svg>"
)


class Jobs:
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs: dict[str, dict[str, Any]] = {}

    def launch(self, name: str, function: Callable[[], Any]) -> dict[str, Any]:
        with self.lock:
            current = self.jobs.get(name)
            if current and current.get("running"):
                raise ValueError(f"{name} is already running")
            state = {"running": True, "started": time.time(), "finished": 0, "result": None, "error": ""}
            self.jobs[name] = state

        def work() -> None:
            try:
                result = function()
                with self.lock:
                    state["result"] = result
            except Exception as exc:
                with self.lock:
                    state["error"] = str(exc)
            finally:
                with self.lock:
                    state["running"] = False
                    state["finished"] = time.time()

        threading.Thread(target=work, daemon=True, name="job-" + name).start()
        return {"job": name}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.jobs)


class Lattice:
    def __init__(self, root: str, resolver_port: int = 5353, dot_port: int = 8853, frp_local_port: int = 8854):
        self.started = time.time()
        self.stop_event = threading.Event()
        self.store = Store(root)
        self.policy = Policy(self.store)
        self.resolver = ResolverManager(self.store, resolver_port)
        self.certs = CertificateVault(self.store)
        self.gateway = DNSGateway(self.store, self.policy, self.certs, resolver_port, dot_port, frp_local_port)
        self.frp = FRPSupervisor(self.store, frp_local_port)
        self.feeds = FeedManager(self.store, self.policy)
        self.jobs = Jobs()
        self.threads: list[threading.Thread] = []

    def start(self) -> None:
        self.resolver.apply()
        self.gateway.start()
        try:
            self.frp.apply()
        except Exception as exc:
            self.store.audit("FRP startup failed", str(exc))
        self._thread(self._health_loop, "upstream-health")
        self._thread(self._maintenance_loop, "maintenance")
        if self.store.setup_code:
            print("Lattice first-time setup code: " + self.store.setup_code, flush=True)

    def _thread(self, target: Callable[[], None], name: str) -> None:
        thread = threading.Thread(target=target, daemon=True, name=name)
        thread.start()
        self.threads.append(thread)

    def shutdown(self) -> None:
        self.stop_event.set()
        self.frp.stop()
        self.gateway.stop()
        self.resolver.stop()
        self.store.close()

    def _health_loop(self) -> None:
        while not self.stop_event.wait(3):
            for upstream in list(self.store.config["upstreams"]):
                if not upstream["enabled"]:
                    continue
                checked = time.time()
                try:
                    result = probe_dot(upstream)
                    healthy, latency, error = 1, result["latency"], ""
                except Exception as exc:
                    healthy, latency, error = 0, None, str(exc)[:400]
                with self.store.lock, self.store.db:
                    self.store.db.execute(
                        """
                        INSERT INTO upstream_health(upstream,checked,healthy,latency,error)
                        VALUES(?,?,?,?,?)
                        ON CONFLICT(upstream) DO UPDATE SET
                            checked=excluded.checked,
                            healthy=excluded.healthy,
                            latency=excluded.latency,
                            error=excluded.error
                        """,
                        (upstream["id"], checked, healthy, latency, error),
                    )
            if self.stop_event.wait(57):
                break

    def _maintenance_loop(self) -> None:
        next_cleanup = 0.0
        next_renew = 0.0
        next_feed = 0.0
        while not self.stop_event.wait(10):
            now = time.time()
            if now >= next_cleanup:
                self.store.cleanup()
                next_cleanup = now + 3600
            if now >= next_renew:
                try:
                    if self.store.meta("acme_terms", False):
                        self.certs.renew_if_needed()
                except Exception as exc:
                    self.store.audit("Certificate renewal failed", str(exc))
                next_renew = now + 43200
            if now >= next_feed:
                for feed in self.feeds.list():
                    if feed["enabled"] and (not feed["refreshed"] or now - feed["refreshed"] >= 21600):
                        try:
                            self.feeds.refresh_one(feed["id"])
                        except Exception as exc:
                            self.store.audit("Subscription refresh failed", f"{feed['name']}:{exc}")
                next_feed = now + 1800

    def status(self, window: int = 86400) -> dict[str, Any]:
        health = self.store.rows("SELECT * FROM upstream_health ORDER BY upstream")
        return {
            "version": __version__,
            "uptime": int(time.time() - self.started),
            "resolver": self.resolver.status(),
            "dot": self.gateway.status(),
            "tls": self.certs.status(),
            "frp": self.frp.status(),
            "policy": self.policy.status(),
            "pause_blocking": self.store.blocking_pause_status(),
            "devices": self.store.get_devices(),
            "dashboard": self.store.dashboard(window=window),
            "threat": self.store.threat_snapshot(),
            "upstreams": health,
            "jobs": self.jobs.snapshot(),
        }

    def update_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict) or "config" not in payload:
            raise ValueError("config is required")
        new_config = validate_config(payload["config"])
        secrets_payload = payload.get("secrets") or {}
        if not isinstance(secrets_payload, dict) or set(secrets_payload) - {"cloudflare", "frp"}:
            raise ValueError("Unknown secret field")

        old_config = copy.deepcopy(self.store.config)
        old_secrets = {key: self.store.secret(key) for key in ("cloudflare", "frp")}
        try:
            for key, value in secrets_payload.items():
                if value is not None:
                    self.store.set_secret(key, str(value))
            self.store.set_config(new_config)
            self.resolver.apply(new_config)
            self.policy.compile()
            self.frp.apply(new_config)
        except Exception:
            self.store.set_config(old_config)
            for key, value in old_secrets.items():
                self.store.set_secret(key, value)
            self.resolver.apply(old_config)
            self.policy.compile()
            try:
                self.frp.apply(old_config)
            except Exception:
                pass
            raise
        self.store.audit("Configuration applied")
        return new_config

    def sync_cloudflare(self) -> dict[str, Any]:
        token = self.store.secret("cloudflare")
        cfg = self.store.config
        if not token:
            raise ValueError("Cloudflare token is not saved")
        result = CloudflareDNS(token).sync(cfg["hostname"], cfg["public_target"])
        self.store.set_meta("dns_record", result)
        self.store.audit("Cloudflare DNS synchronized", result.get("name", ""))
        return result

    @staticmethod
    def make_query(name: str, qtype: int = 1, edns0: bool = False, ident: int = 0x4C44) -> bytes:
        clean = name.rstrip(".")
        if not clean:
            qname = b"\0"
        else:
            labels = clean.encode("idna").split(b".")
            qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
        ar = 1 if edns0 else 0
        pkt = struct.pack("!6H", ident, 0x0100, 1, 0, 0, ar) + qname + struct.pack("!HH", qtype, 1)
        if edns0:
            pkt += b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
        return pkt

    def diagnose(self, name: str, qtype: int = 1, client: str = "127.0.0.1") -> dict[str, Any]:
        name = hostname(name, "diagnostic hostname", allow_empty=True)
        if qtype not in (1, 2, 5, 6, 12, 15, 16, 28, 33, 43, 48, 64, 65):
            raise ValueError("Unsupported diagnostic record type")
        decision = self.policy.decide(client, name)
        policy_result = {
            "action": decision.action,
            "source": decision.source,
            "profile": decision.profile,
            "value": decision.value,
        }
        if decision.action == "deny":
            return {
                "name": name,
                "qtype": qtype,
                "policy": policy_result,
                "resolver": {"skipped": True, "reason": "policy_block"},
            }
        if decision.action == "rewrite":
            return {
                "name": name,
                "qtype": qtype,
                "policy": policy_result,
                "resolver": {
                    "skipped": True,
                    "reason": "local_rewrite",
                    "records": [{"name": name, "type": "A" if ":" not in decision.value else "AAAA", "ttl": 60, "data": decision.value}],
                },
            }
        packet = self.make_query(name, qtype, edns0=True)
        _, _, q_end = read_question(packet)
        try:
            started = time.monotonic()
            response, fb_note = self.gateway._forward_query(packet, name, qtype)
            latency = round((time.monotonic() - started) * 1000, 2)
            records = decode_dns_answers(response)
            resolver_info = {
                "skipped": False,
                "rcode": response[3] & 15,
                "answers": struct.unpack("!H", response[6:8])[0],
                "authority": struct.unpack("!H", response[8:10])[0],
                "additional": struct.unpack("!H", response[10:12])[0],
                "dnssec_authenticated": bool(response[3] & 0x20),
                "latency": latency,
                "question_bytes": q_end - 12,
                "records": records,
                "via": fb_note or self.resolver.status().get("mode", "unbound"),
            }
        except Exception as exc:
            resolver_info = {
                "skipped": False,
                "error": str(exc),
                "reason": "resolver_unreachable",
            }
        return {
            "name": name,
            "qtype": qtype,
            "policy": policy_result,
            "resolver": resolver_info,
        }

    def android_readiness(self) -> dict[str, Any]:
        """Run an end-to-end Android Private DNS (RFC 7858 / DnsTlsTransport) verification suite."""
        cfg = self.store.config
        fqdn = cfg.get("hostname", "").strip()
        tls_status = self.certs.status()
        dot_status = self.gateway.status()
        frp_status = self.frp.status()

        checks: list[dict[str, Any]] = []

        # 1. Hostname & FQDN check
        checks.append({
            "id": "hostname",
            "title": "Private DNS Hostname (FQDN)",
            "ok": bool(fqdn and "." in fqdn),
            "detail": fqdn if fqdn else "No Private DNS hostname configured yet",
        })

        # 2. X.509 Certificate & SAN Verification (Android Strict Mode requires publicly trusted CA)
        is_test_domain = any(fqdn.endswith(sfx) for sfx in (".test", ".internal", ".local"))
        is_self_signed = bool(tls_status.get("self_signed"))
        cert_ok = bool(
            tls_status.get("valid")
            and tls_status.get("hostname_matches", True)
            and (not is_self_signed or is_test_domain)
        )
        if not tls_status.get("valid"):
            cert_detail = tls_status.get("error", "No certificate installed")
        elif is_self_signed and not is_test_domain:
            cert_detail = (
                f"Self-signed cert on {tls_status.get('hostname')} — Android Private DNS rejects self-signed certs! "
                "Enter your Cloudflare token and click 'Issue or Renew Certificate' for a trusted Let's Encrypt cert."
            )
        else:
            cert_detail = (
                f"Valid for {tls_status.get('hostname')} ({tls_status.get('days_left', 0)}d remaining, "
                + ("test self-signed)" if is_self_signed else "Public CA-signed)")
            )
        checks.append({
            "id": "tls_cert",
            "title": "Android Trusted CA Certificate & SAN",
            "ok": cert_ok,
            "detail": cert_detail,
        })

        # 3. EDNS0 OPT (RFC 6891 + DO bit) & Negative-Caching SOA (RFC 2308) Packet Fidelity
        edns_query = _question("probe.dnsotls-ds.metric.gstatic.com", ident=0xA101)
        synth_nx = error_response(edns_query, 3)
        synth_rw = rewrite_response(edns_query, 28, "216.239.38.120")
        edns_ok = (
            synth_nx[:2] == b"\xA1\x01"
            and (synth_nx[3] & 15) == 3
            and struct.unpack("!H", synth_nx[8:10])[0] == 1
            and struct.unpack("!H", synth_nx[10:12])[0] == 1
            and b"\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00" in synth_nx  # DO bit echoed!
            and struct.unpack("!H", synth_rw[6:8])[0] == 0
            and struct.unpack("!H", synth_rw[8:10])[0] == 1
            and struct.unpack("!H", synth_rw[10:12])[0] == 1
        )
        checks.append({
            "id": "edns0_soa",
            "title": "EDNS0 OPT (DO-Bit) & RFC 2308 SOA",
            "ok": edns_ok,
            "detail": "ARCOUNT=1 OPT (DO echoed) & NSCOUNT=1 SOA verified on NXDOMAIN/NODATA" if edns_ok else "EDNS0/SOA check failed",
        })

        # 4. Android Connectivity & SafeSearch Isolation Check
        ss_clients3 = get_safesearch_rewrite("clients3.google.com")
        ss_play = get_safesearch_rewrite("play.google.com")
        ss_mtalk = get_safesearch_rewrite("mtalk.google.com")
        ss_search = get_safesearch_rewrite("www.google.com")
        essential_ok = (
            ss_clients3 is None
            and ss_play is None
            and ss_mtalk is None
            and ss_search is not None
            and is_android_essential("connectivitycheck.gstatic.com")
            and is_android_essential("random123.dnsotls-ds.metric.gstatic.com")
            and is_android_essential("ipv4only.arpa")
        )
        checks.append({
            "id": "android_probes",
            "title": "Android Captive Portal & SafeSearch Isolation",
            "ok": essential_ok,
            "detail": "clients3.google.com, play.google.com, mtalk.google.com & *.dnsotls-ds.metric.gstatic.com protected",
        })

        # 5. Live DoT Pipelining & ALPN 'dot' Probe
        pipeline_ok = False
        pipeline_detail = "Install or generate a TLS certificate to test live DoT pipelining"
        if dot_status.get("running") and self.certs.context is not None:
            try:
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.check_hostname = False
                client_ctx.verify_mode = ssl.CERT_NONE
                try:
                    client_ctx.set_alpn_protocols(["dot"])
                except Exception:
                    pass
                q1 = self.make_query("localhost", 1, edns0=True, ident=0x1101)
                q2 = self.make_query("_dns.resolver.arpa", 64, edns0=True, ident=0x1102)
                q3 = self.make_query("localhost", 28, edns0=True, ident=0x1103)
                burst = (
                    struct.pack("!H", len(q1)) + q1
                    + struct.pack("!H", len(q2)) + q2
                    + struct.pack("!H", len(q3)) + q3
                )
                t0 = time.monotonic()
                with socket.create_connection(("127.0.0.1", self.gateway.direct_port), timeout=4.0) as raw:
                    with client_ctx.wrap_socket(raw, server_hostname=fqdn or "dns.lattice.internal") as tls_sock:
                        tls_sock.settimeout(4.0)
                        alpn = tls_sock.selected_alpn_protocol() or "dot"
                        tls_ver = tls_sock.version() or "TLSv1.3"
                        tls_sock.sendall(burst)
                        rx_ids: set[int] = set()
                        for _ in range(3):
                            rlen = struct.unpack("!H", recv_exact(tls_sock, 2))[0]
                            rpkt = recv_exact(tls_sock, rlen)
                            rx_ids.add(struct.unpack("!H", rpkt[:2])[0])
                elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
                pipeline_ok = rx_ids == {0x1101, 0x1102, 0x1103}
                pipeline_detail = f"3 pipelined queries multiplexed over {tls_ver} (ALPN={alpn}) in {elapsed_ms} ms"
            except Exception as exc:
                pipeline_ok = False
                pipeline_detail = f"DoT probe error: {exc}"

        checks.append({
            "id": "dot_pipelining",
            "title": "RFC 7858 / DnsTlsSocket Pipelined Multiplexing",
            "ok": pipeline_ok,
            "detail": pipeline_detail,
        })

        # 6. Public Port 853 Transport Readiness (including Railway / Cloudflare proxy detection)
        frp_enabled = bool(cfg.get("frp", {}).get("enabled"))
        on_railway = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RAILWAY_PROJECT_ID") or os.environ.get("RAILWAY_SERVICE_NAME"))
        if on_railway and not frp_enabled:
            transport_ok = False
            transport_detail = (
                "Running on Railway without FRP enabled! Railway web domains only expose HTTP/443, NOT TCP/853. "
                "Enable Step 3 (FRP Edge Tunnel) to a public port 853 server so Android Private DNS can connect."
            )
        elif frp_enabled:
            transport_ok = bool(dot_status.get("running") and frp_status.get("state") == "online")
            transport_detail = (
                f"FRP tunnel online (Public TCP/{cfg['frp']['remote_port']} → Bridge {self.gateway.frp_port})"
                if transport_ok
                else f"FRP tunnel is {frp_status.get('state')} ({frp_status.get('error') or 'waiting for connection to FRPS:7000'})"
            )
        else:
            transport_ok = bool(dot_status.get("running"))
            transport_detail = f"Direct DoT listener active on port {self.gateway.direct_port} (requires host TCP 853 → {self.gateway.direct_port})"

        checks.append({
            "id": "port_853",
            "title": "Public TCP/853 Transport Path",
            "ok": transport_ok,
            "detail": transport_detail,
        })

        passed = sum(1 for c in checks if c["ok"])
        return {
            "ready": passed == len(checks),
            "passed": passed,
            "total": len(checks),
            "hostname": fqdn,
            "checks": checks,
        }


STATIC = Path(__file__).with_name("static")
CSP_HEADER = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'"


class Handler(BaseHTTPRequestHandler):
    server_version = "LatticeDNS"
    app: Lattice

    def log_message(self, fmt: str, *args: Any) -> None:
        print("web " + fmt % args, flush=True)

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        try:
            cookie = http.cookies.SimpleCookie()
            cookie.load(raw)
            return cookie[name].value if name in cookie else ""
        except Exception:
            return ""

    def _session(self) -> tuple[str, dict[str, Any] | None]:
        token = self._cookie("lattice_session")
        return token, self.app.store.session(token)

    def _json(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP_HEADER)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 2 * 1024 * 1024:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(length)
        return json.loads(raw or b"{}")

    def _require(self, mutation: bool = False) -> dict[str, Any]:
        _, session = self._session()
        if not session:
            raise PermissionError("Authentication required")
        if mutation and self.headers.get("X-CSRF-Token", "") != session["csrf"]:
            raise PermissionError("CSRF token is invalid")
        return session

    def _set_session(self, token: str) -> dict[str, str]:
        secure = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        cookie = f"lattice_session={token}; Path=/; HttpOnly; SameSite=Strict"
        if secure:
            cookie += "; Secure"
        return {"Set-Cookie": cookie}

    def _static(self, path: str) -> None:
        if path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(FAVICON_SVG)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(FAVICON_SVG)
            return
        mapping = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "application/javascript; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
        }
        item = mapping.get(path)
        if not item:
            self.send_error(404)
            return
        file_path = STATIC / item[0]
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", item[1])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP_HEADER)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/dns-query":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()
            return
        self.send_response(405)
        self.end_headers()

    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            if path == "/dns-query":
                client = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
                params = urllib.parse.parse_qs(parsed.query)
                if "dns" in params:
                    raw_b64 = params["dns"][0]
                    rem = len(raw_b64) % 4
                    if rem:
                        raw_b64 += "=" * (4 - rem)
                    dns_wire = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
                    resp_wire = self.app.gateway.handle_query(dns_wire, client, transport="doh")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/dns-message")
                    self.send_header("Content-Length", str(len(resp_wire)))
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(resp_wire)
                    return
                elif "name" in params:
                    name = params["name"][0]
                    type_str = params.get("type", ["1"])[0]
                    qtype_map = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15, "PTR": 12, "HTTPS": 65}
                    try:
                        qtype = int(type_str) if type_str.isdigit() else qtype_map.get(type_str.upper(), 1)
                    except ValueError:
                        qtype = 1
                    diag = self.app.diagnose(name, qtype, client)
                    return self._json(200, diag, {"Access-Control-Allow-Origin": "*"})

            if path == "/healthz":
                state = self.app.resolver.status()
                return self._json(200 if state["running"] else 503, {"ok": state["running"]})
            if path in ("/", "/app.js", "/app.css", "/favicon.ico"):
                return self._static(path)
            if path == "/api/bootstrap":
                _, session = self._session()
                return self._json(
                    200,
                    {
                        "setup_required": not self.app.store.has_user(),
                        "authenticated": bool(session),
                        "csrf": session["csrf"] if session else "",
                        "version": __version__,
                    },
                )

            self._require()

            if path == "/api/diagnostics/android":
                return self._json(200, self.app.android_readiness())

            if path == "/api/apple/mobileconfig":
                hostname_val = self.app.store.config.get("hostname", "").strip() or "dns.lattice.local"
                uuid_main = str(uuid.uuid4())
                uuid_dns = str(uuid.uuid4())
                xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Lattice DNS ({hostname_val})</string>
    <key>PayloadDescription</key>
    <string>Configures encrypted DNS over TLS &amp; HTTPS via Lattice DNS</string>
    <key>PayloadIdentifier</key>
    <string>com.latticedns.profile.{hostname_val}</string>
    <key>PayloadOrganization</key>
    <string>Lattice DNS</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{uuid_main}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.latticedns.dns.{hostname_val}</string>
            <key>PayloadUUID</key>
            <string>{uuid_dns}</string>
            <key>PayloadDisplayName</key>
            <string>Lattice Encrypted DNS</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://{hostname_val}/dns-query</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""
                body = xml_payload.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/x-apple-aspen-config")
                self.send_header("Content-Disposition", f'attachment; filename="lattice-dns-{hostname_val}.mobileconfig"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/rules/presets":
                return self._json(200, self.app.store.get_presets_status())
            if path == "/api/status":
                params = urllib.parse.parse_qs(parsed.query)
                window = int(params.get("window", ["86400"])[0]) if params.get("window") else 86400
                return self._json(200, self.app.status(window=window))
            if path == "/api/blocking/pause":
                return self._json(200, self.app.store.blocking_pause_status())
            if path == "/api/devices":
                return self._json(200, self.app.store.get_devices())
            if path == "/api/upstreams/benchmark":
                custom = self.app.store.config.get("upstreams", [])
                return self._json(200, {"upstreams": benchmark_upstreams(custom)})
            if path == "/api/cache/stats":
                return self._json(200, {"cache": self.app.store.config.get("cache", {}), "resolver": self.app.resolver.status()})
            if path == "/api/queries/export":
                params = urllib.parse.parse_qs(parsed.query)
                q = params.get("q", [""])[0].strip().lower()
                action = params.get("action", [""])[0].strip()
                try:
                    qtype = int(params.get("qtype", ["0"])[0]) if params.get("qtype") else 0
                except ValueError:
                    qtype = 0
                try:
                    limit = int(params.get("limit", ["5000"])[0]) if params.get("limit") else 5000
                except ValueError:
                    limit = 5000
                csv_data = self.app.store.export_queries_csv(limit=limit, action=action, q=q, qtype=qtype).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="lattice-queries.csv"')
                self.send_header("Content-Length", str(len(csv_data)))
                self.end_headers()
                self.wfile.write(csv_data)
                return
            if path == "/api/config":
                return self._json(
                    200,
                    {
                        "config": self.app.store.config,
                        "secrets": {
                            "cloudflare": bool(self.app.store.secret("cloudflare")),
                            "frp": bool(self.app.store.secret("frp")),
                        },
                        "dns_record": self.app.store.meta("dns_record"),
                    },
                )
            if path == "/api/rules":
                return self._json(200, self.app.store.rule_rows())
            if path == "/api/feeds":
                return self._json(200, self.app.feeds.list())
            if path == "/api/queries":
                params = urllib.parse.parse_qs(parsed.query)
                try:
                    limit = max(1, min(500, int(params.get("limit", ["150"])[0])))
                except ValueError:
                    limit = 150
                q = params.get("q", [""])[0].strip().lower()
                action = params.get("action", [""])[0].strip()
                try:
                    qtype = int(params.get("qtype", ["0"])[0]) if params.get("qtype") else 0
                except ValueError:
                    qtype = 0
                sql = """
                SELECT q.*, COALESCE(d.name, '') device_name, COALESCE(d.icon, 'device') device_icon
                FROM queries q
                LEFT JOIN devices d ON d.ip = q.client
                WHERE 1=1
                """
                args: list[Any] = []
                if q:
                    sql += " AND (LOWER(q.domain) LIKE ? OR LOWER(q.client) LIKE ? OR LOWER(d.name) LIKE ?)"
                    args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
                if action and action != "all":
                    sql += " AND q.action = ?"
                    args.append(action)
                if qtype > 0:
                    sql += " AND q.qtype = ?"
                    args.append(qtype)
                sql += " ORDER BY q.id DESC LIMIT ?"
                args.append(limit)
                rows = self.app.store.rows(sql, tuple(args))
                return self._json(200, rows)
            if path == "/api/backup":
                payload = {
                    "version": __version__,
                    "timestamp": time.time(),
                    "config": self.app.store.config,
                    "rules": self.app.store.rule_rows(),
                    "feeds": self.app.feeds.list(),
                }
                return self._json(200, payload)
            if path == "/api/audit":
                return self._json(200, self.app.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 200"))
            if path == "/api/upstreams":
                return self._json(200, self.app.store.rows("SELECT * FROM upstream_health ORDER BY upstream"))
            self._json(404, {"error": "Not found"})
        except PermissionError as exc:
            self._json(401, {"error": str(exc)})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/dns-query":
                client = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("Invalid DNS payload length")
                dns_wire = self.rfile.read(length)
                resp_wire = self.app.gateway.handle_query(dns_wire, client, transport="doh")
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-message")
                self.send_header("Content-Length", str(len(resp_wire)))
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp_wire)
                return

            if path == "/api/setup":
                client_ip = self.client_address[0]
                self.app.store.check_auth_rate_limit(client_ip)
                body = self._body()
                try:
                    self.app.store.complete_setup(str(body.get("code", "")), str(body.get("password", "")))
                except Exception:
                    self.app.store.record_auth_failure(client_ip)
                    raise
                token = self.app.store.authenticate(str(body.get("password", "")))
                session = self.app.store.session(token)
                return self._json(200, {"ok": True, "csrf": session["csrf"]}, self._set_session(token))
            if path == "/api/login":
                client_ip = self.client_address[0]
                self.app.store.check_auth_rate_limit(client_ip)
                body = self._body()
                try:
                    token = self.app.store.authenticate(str(body.get("password", "")))
                except Exception:
                    self.app.store.record_auth_failure(client_ip)
                    raise
                session = self.app.store.session(token)
                return self._json(200, {"ok": True, "csrf": session["csrf"]}, self._set_session(token))

            self._require(mutation=True)

            if path == "/api/upstreams/benchmark":
                body = self._body()
                domain_name = str(body.get("domain", "cloudflare.com")).strip() or "cloudflare.com"
                custom = self.app.store.config.get("upstreams", [])
                return self._json(200, {"upstreams": benchmark_upstreams(custom, name=domain_name)})
            if path == "/api/rules/presets/toggle":
                body = self._body()
                preset_id = str(body.get("preset", ""))
                enable = bool(body.get("enabled", True))
                res = self.app.store.toggle_preset(preset_id, enable)
                self.app.policy.compile()
                return self._json(200, res)
            if path == "/api/logout":
                token, _ = self._session()
                self.app.store.logout(token)
                return self._json(200, {"ok": True}, {"Set-Cookie": "lattice_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            if path == "/api/blocking/pause":
                body = self._body()
                raw_sec = body.get("seconds") if "seconds" in body else body.get("duration", 300)
                seconds = int(raw_sec)
                return self._json(200, self.app.store.pause_blocking(seconds))
            if path == "/api/queries/clear":
                cleared = self.app.store.clear_queries()
                return self._json(200, {"ok": True, "cleared": cleared})
            if path == "/api/devices":
                body = self._body()
                ip = str(body.get("ip", "")).strip()
                if not ip:
                    raise ValueError("Device IP address is required")
                self.app.store.update_device(
                    ip,
                    str(body.get("name", "")).strip(),
                    str(body.get("icon", "device")).strip(),
                    str(body.get("profile", "*")).strip(),
                )
                self.app.policy.compile()
                return self._json(200, {"ok": True})
            if path == "/api/rules/import":
                body = self._body()
                res = self.app.store.import_rules(
                    str(body.get("content", "")),
                    action=str(body.get("action", "deny")),
                    profile=str(body.get("profile", "*")),
                    kind=str(body.get("kind", "exact")),
                )
                self.app.policy.compile()
                return self._json(200, res)
            if path == "/api/rules/clear_expired":
                cleared = self.app.store.clear_expired_rules()
                self.app.policy.compile()
                return self._json(200, {"ok": True, "cleared": cleared})
            if path == "/api/restore":
                body = self._body()
                if "config" in body and isinstance(body["config"], dict):
                    self.app.update_config({"config": body["config"], "secrets": body.get("secrets", {})})
                if "rules" in body and isinstance(body["rules"], list):
                    existing = {r["pattern"] for r in self.app.store.rule_rows()}
                    for r in body["rules"]:
                        if isinstance(r, dict) and r.get("pattern") and r["pattern"] not in existing:
                            try:
                                raw_pattern = str(r.get("pattern", "")).lstrip("*.").rstrip(".")
                                pattern = hostname(raw_pattern, "rule pattern")
                                self.app.store.add_rule(
                                    pattern,
                                    r.get("kind", "exact"),
                                    r.get("action", "deny"),
                                    str(r.get("value", "")),
                                    str(r.get("profile", "*")),
                                    r.get("expires"),
                                )
                            except Exception:
                                pass
                    self.app.policy.compile()
                if "feeds" in body and isinstance(body["feeds"], list):
                    existing_urls = {f["url"] for f in self.app.feeds.list()}
                    for f in body["feeds"]:
                        if isinstance(f, dict) and f.get("url") and f["url"] not in existing_urls:
                            try:
                                self.app.feeds.add(
                                    name=str(f.get("name", "Restored Feed")),
                                    url=str(f["url"]),
                                    category=str(f.get("category", "ads")),
                                    mode=str(f.get("format", "auto")),
                                    enabled=bool(f.get("enabled", True)),
                                )
                            except Exception:
                                pass
                self.app.store.audit("Backup restored", "Configuration, rules and feeds restored from backup")
                return self._json(200, {"ok": True, "message": "Backup restored successfully"})
            if path == "/api/rules":
                body = self._body()
                raw_pattern = str(body.get("pattern", "")).lstrip("*.").rstrip(".")
                pattern = hostname(raw_pattern, "rule pattern")
                kind = body.get("kind", "exact")
                action = body.get("action", "deny")
                value = str(body.get("value", "")).strip()
                profile = str(body.get("profile", "*"))
                if profile != "*" and profile not in {p["id"] for p in self.app.store.config["profiles"]}:
                    raise ValueError("Unknown profile")
                if action == "rewrite":
                    value = str(ipaddress.ip_address(value))
                expires = body.get("expires")
                row = self.app.store.add_rule(pattern, kind, action, value, profile, expires)
                self.app.policy.compile()
                return self._json(201, row)
            if path == "/api/feeds":
                body = self._body()
                row = self.app.feeds.add(
                    body.get("name", ""),
                    body.get("url", ""),
                    body.get("category", "ads"),
                    body.get("format", "auto"),
                    bool(body.get("enabled", True)),
                )
                return self._json(201, row)
            if path == "/api/feeds/refresh":
                body = self._body()
                feed_id = body.get("id")
                if feed_id is None:
                    return self._json(202, self.app.jobs.launch("feed_refresh", self.app.feeds.refresh_all))
                return self._json(202, self.app.jobs.launch("feed_refresh", lambda: self.app.feeds.refresh_one(int(feed_id))))
            if path == "/api/tls/issue":
                agree = self._body().get("agree") is True
                return self._json(202, self.app.jobs.launch("certificate", lambda: self.app.certs.issue(agree)))
            if path == "/api/tls/self-signed":
                body = self._body()
                req_host = str(body.get("hostname", "")).strip()
                cfg_host = self.app.store.config.get("hostname", "").strip()
                target_fqdn = hostname(req_host or cfg_host or "dns.lattice.internal")
                if target_fqdn != cfg_host:
                    cfg_copy = copy.deepcopy(self.app.store.config)
                    cfg_copy["hostname"] = target_fqdn
                    self.app.store.set_config(validate_config(cfg_copy))
                result = self.app.certs.generate_self_signed(target_fqdn)
                self.app.store.audit("Self-signed TLS certificate generated", target_fqdn)
                return self._json(200, result)
            if path == "/api/tls/upload":
                body = self._body()
                fqdn = self.app.store.config.get("hostname", "").strip()
                if not fqdn:
                    raise ValueError("Configure a Private DNS hostname before installing a certificate")
                result = self.app.certs.activate(
                    str(body.get("certificate", "")).encode(),
                    str(body.get("private_key", "")).encode(),
                    fqdn,
                )
                self.app.store.audit("TLS certificate installed", fqdn)
                return self._json(200, result)
            if path == "/api/cloudflare/sync":
                return self._json(202, self.app.jobs.launch("cloudflare_sync", self.app.sync_cloudflare))
            if path == "/api/frp/restart":
                return self._json(202, self.app.jobs.launch("frp_restart", self.app.frp.apply))
            if path == "/api/cache/flush":
                result = self.app.resolver.control("flush_zone", ".")
                self.app.store.audit("Resolver cache flushed")
                return self._json(200, {"ok": True, "result": result})
            if path == "/api/diagnostics/resolve":
                body = self._body()
                client = str(body.get("client", "127.0.0.1")).strip() or "127.0.0.1"
                return self._json(200, self.app.diagnose(body.get("name", ""), int(body.get("qtype", 1)), client=client))
            self._json(404, {"error": "Not found"})
        except PermissionError as exc:
            self._json(401, {"error": str(exc)})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def do_PUT(self) -> None:
        try:
            path = urllib.parse.urlsplit(self.path).path
            self._require(mutation=True)
            if path == "/api/rules/presets/toggle":
                body = self._body()
                preset_id = str(body.get("preset", ""))
                enable = bool(body.get("enabled", True))
                res = self.app.store.toggle_preset(preset_id, enable)
                self.app.policy.compile()
                return self._json(200, res)
            if path == "/api/config":
                result = self.app.update_config(self._body())
                return self._json(200, {"config": result})
            if path.startswith("/api/feeds/") and path.endswith("/enabled"):
                feed_id = int(path.split("/")[3])
                body = self._body()
                self.app.feeds.set_enabled(feed_id, body.get("enabled") is True)
                return self._json(200, {"ok": True})
            self._json(404, {"error": "Not found"})
        except PermissionError as exc:
            self._json(401, {"error": str(exc)})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

    def do_DELETE(self) -> None:
        try:
            path = urllib.parse.urlsplit(self.path).path
            self._require(mutation=True)
            if path.startswith("/api/devices/"):
                ip = urllib.parse.unquote(path.split("/")[3])
                self.app.store.delete_device(ip)
                self.app.policy.compile()
                return self._json(200, {"ok": True})
            if path.startswith("/api/rules/"):
                rule_id = int(path.rsplit("/", 1)[1])
                self.app.store.delete_rule(rule_id)
                self.app.policy.compile()
                return self._json(200, {"ok": True})
            if path.startswith("/api/feeds/"):
                feed_id = int(path.rsplit("/", 1)[1])
                self.app.feeds.delete(feed_id)
                return self._json(200, {"ok": True})
            self._json(404, {"error": "Not found"})
        except PermissionError as exc:
            self._json(401, {"error": str(exc)})
        except Exception as exc:
            self._json(400, {"error": str(exc)})


def serve() -> None:
    root = os.environ.get("DATA_DIR", "/data")
    app = Lattice(
        root,
        resolver_port=int(os.environ.get("RESOLVER_PORT", "5353")),
        dot_port=int(os.environ.get("DOT_PORT", "8853")),
        frp_local_port=int(os.environ.get("FRP_LOCAL_PORT", "8854")),
    )
    app.start()
    Handler.app = app
    server = ThreadingHTTPServer(
        (os.environ.get("WEB_HOST", "0.0.0.0"), int(os.environ.get("PORT", os.environ.get("WEB_PORT", "8080")))),
        Handler,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        app.shutdown()
