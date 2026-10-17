"""Validated Unbound lifecycle, suffix routing, smart IPv6 upstream detection, and upstream health probes."""
from __future__ import annotations

import concurrent.futures
import os
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .store import atomic_write

SBIN_PATH = "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:" + os.environ.get("PATH", "")


def _find_bin(name: str) -> str | None:
    return shutil.which(name, path=SBIN_PATH)


class ResolverManager:
    def __init__(self, store, port: int = 5353, control_port: int = 8953):
        self.store = store
        self.port = port
        self.control_port = control_port
        self.root = store.root / "unbound"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "unbound.conf"
        self.process: subprocess.Popen | None = None
        self.embedded = True
        self.lock = threading.RLock()
        self.error = ""
        self.started = time.time()

    def ensure_anchor(self) -> Path | None:
        target = self.root / "root.key"
        if target.exists() and target.stat().st_size > 0:
            return target
        for source in (Path("/usr/share/dns/root.key"), Path("/var/lib/unbound/root.key")):
            if source.exists():
                shutil.copyfile(source, target)
                target.chmod(0o600)
                return target
        anchor_bin = _find_bin("unbound-anchor")
        if anchor_bin:
            try:
                subprocess.run([anchor_bin, "-a", str(target)], capture_output=True, timeout=30, check=True)
                if target.exists() and target.stat().st_size > 0:
                    return target
            except Exception:
                pass
        try:
            target.write_text(
                ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237E7F5EC8D\n"
            )
            target.chmod(0o600)
            return target
        except Exception:
            return None

    @staticmethod
    def _forward_line(upstream: dict[str, Any]) -> str:
        return f'    forward-addr: "{upstream["address"]}@{upstream["port"]}#{upstream["sni"]}"'

    def render(self, cfg: dict[str, Any]) -> str:
        cache = cfg["cache"]
        anchor = self.ensure_anchor() if cfg["dnssec"] else None
        has_ipv6_upstream = any(":" in u.get("address", "") for u in cfg.get("upstreams", []) if u.get("enabled", True))
        lines = [
            "server:",
            f"    interface: 127.0.0.1@{self.port}",
            "    do-ip4: yes",
            f'    do-ip6: {"yes" if has_ipv6_upstream else "no"}',
            "    prefer-ip4: yes",
            "    do-udp: yes",
            "    do-tcp: yes",
            "    access-control: 127.0.0.0/8 allow",
            "    access-control: ::1 allow",
            '    username: ""',
            '    chroot: ""',
            '    directory: ""',
            '    pidfile: ""',
            "    use-syslog: no",
            '    logfile: ""',
            "    verbosity: 1",
            "    num-threads: 2",
            "    outgoing-num-tcp: 64",
            "    incoming-num-tcp: 64",
            "    num-queries-per-thread: 512",
            f'    edns-buffer-size: {cfg["edns_buffer_size"]}',
            f'    msg-cache-size: {cache["message_mb"]}m',
            f'    rrset-cache-size: {cache["rrset_mb"]}m',
            f'    prefetch: {"yes" if cache["prefetch"] else "no"}',
            f'    serve-expired: {"yes" if cache["serve_expired"] else "no"}',
            f'    serve-expired-ttl: {cache["serve_expired_ttl"]}',
            "    infra-host-ttl: 15",
            "    infra-keep-probing: yes",
            "    rrset-roundrobin: yes",
            "    hide-identity: yes",
            "    hide-version: yes",
            "    minimal-responses: yes",
            "    qname-minimisation: yes",
            "    harden-glue: yes",
            "    harden-dnssec-stripped: yes",
            "    harden-below-nxdomain: yes",
            "    aggressive-nsec: yes",
            '    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"',
        ]
        if cfg["dnssec"]:
            if not anchor:
                raise ValueError("DNSSEC trust anchor is unavailable")
            lines += [
                '    module-config: "validator iterator"',
                f'    auto-trust-anchor-file: "{anchor}"',
                "    val-clean-additional: yes",
            ]
        else:
            lines += ['    module-config: "iterator"']

        if cfg.get("rebinding_protection", True):
            lines += [
                "    private-address: 10.0.0.0/8",
                "    private-address: 172.16.0.0/12",
                "    private-address: 192.168.0.0/16",
                "    private-address: 169.254.0.0/16",
                "    private-address: 127.0.0.0/8",
                "    private-address: fd00::/8",
                "    private-address: fe80::/10",
                "    private-address: ::1/128",
            ]
            seen_priv: set[str] = set()
            for rec in cfg.get("local_records", []):
                rec_name = rec["name"].rstrip(".")
                if rec_name not in seen_priv:
                    seen_priv.add(rec_name)
                    lines.append(f'    private-domain: "{rec_name}."')
            for route in cfg.get("routes", []):
                route_suffix = route["suffix"].rstrip(".")
                if route_suffix not in seen_priv:
                    seen_priv.add(route_suffix)
                    lines.append(f'    private-domain: "{route_suffix}."')

        for rec in cfg.get("local_records", []):
            name = rec["name"].rstrip(".")
            rtype = rec["type"]
            val = rec["value"]
            ttl = rec.get("ttl", 300)
            if rtype == "TXT":
                safe_txt = val.replace('"', "").replace("'", "")
                lines.append(f'    local-data: \'{name}. {ttl} IN TXT "{safe_txt}"\'')
            elif rtype == "CNAME":
                target_fqdn = val.rstrip(".") + "."
                lines.append(f'    local-data: "{name}. {ttl} IN CNAME {target_fqdn}"')
            else:
                lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {val}"')
                if rtype in ("A", "AAAA"):
                    lines.append(f'    local-data-ptr: "{val} {ttl} {name}."')

        lines += [
            "",
            "remote-control:",
            "    control-enable: yes",
            "    control-interface: 127.0.0.1",
            f"    control-port: {self.control_port}",
            "    control-use-cert: no",
            "",
        ]

        upstreams = {u["id"]: u for u in cfg["upstreams"] if u["enabled"]}
        for route in sorted(cfg["routes"], key=lambda r: r["suffix"].count("."), reverse=True):
            lines += [
                "forward-zone:",
                f'    name: "{route["suffix"]}."',
                "    forward-tls-upstream: yes",
                "    forward-first: no",
            ]
            for upstream_id in route["upstreams"]:
                lines.append(self._forward_line(upstreams[upstream_id]))
            lines.append("")

        lines += [
            "forward-zone:",
            '    name: "."',
            "    forward-tls-upstream: yes",
            "    forward-first: no",
        ]
        for upstream in upstreams.values():
            lines.append(self._forward_line(upstream))
        lines.append("")
        return "\n".join(lines)

    def apply(self, cfg: dict[str, Any] | None = None) -> None:
        cfg = cfg or self.store.config
        text = self.render(cfg)
        checkconf_bin = _find_bin("unbound-checkconf")
        unbound_bin = _find_bin("unbound")
        if not checkconf_bin or not unbound_bin:
            with self.lock:
                atomic_write(self.path, text)
                self.embedded = True
                self.started = self.started or time.time()
                self.error = ""
            return

        candidate = self.root / "candidate.conf"
        atomic_write(candidate, text)
        check = subprocess.run([checkconf_bin, str(candidate)], capture_output=True, text=True, timeout=15)
        if check.returncode:
            candidate.unlink(missing_ok=True)
            detail = (check.stdout + check.stderr).strip()
            raise ValueError("Resolver configuration validation failed: " + detail[-400:])
        with self.lock:
            if (
                self.process is not None
                and self.process.poll() is None
                and self.path.exists()
                and self.path.read_text() == text
            ):
                candidate.unlink(missing_ok=True)
                self.embedded = False
                self.error = ""
                return
            self.stop()
            atomic_write(self.path, text)
            candidate.unlink(missing_ok=True)
            self.process = subprocess.Popen(
                [unbound_bin, "-d", "-c", str(self.path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.embedded = False
            self.started = time.time()
            self.error = ""
            time.sleep(0.2)
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                self.error = output[-1000:]
                self.process = None
                raise ValueError("Resolver failed to start: " + self.error[-400:])

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
        self.embedded = False

    def control(self, *args: str) -> str:
        ctrl_bin = _find_bin("unbound-control")
        if not ctrl_bin or self.embedded:
            return "ok (embedded resolver cache cleared)"
        cmd = [ctrl_bin, "-c", str(self.path), *args]
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if run.returncode:
            raise ValueError("Resolver control failed: " + (run.stdout + run.stderr).strip()[-300:])
        return run.stdout.strip()

    def status(self) -> dict[str, Any]:
        process = self.process
        running = bool((process and process.poll() is None) or self.embedded)
        return {
            "running": running,
            "pid": process.pid if (process and process.poll() is None) else None,
            "uptime": int(time.time() - self.started) if running and self.started else 0,
            "error": self.error,
            "port": self.port,
            "mode": "embedded-dot" if self.embedded else "unbound",
        }


def _question(name: str, ident: int = 0x4C44) -> bytes:
    clean = name.rstrip(".")
    if not clean:
        qname = b"\0"
    else:
        encoded = clean.encode("idna").split(b".")
        qname = b"".join(bytes([len(label)]) + label for label in encoded) + b"\0"
    header = struct.pack("!6H", ident, 0x0120, 1, 0, 0, 1)
    question = qname + struct.pack("!HH", 1, 1)
    edns0 = b"\0\0\x29\x04\xd0\0\0\x80\0\0\0"
    return header + question + edns0


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("Connection closed")
        data.extend(chunk)
    return bytes(data)


def probe_dot(upstream: dict[str, Any], name: str = "example.com") -> dict[str, Any]:
    packet = _question(name)
    start = time.monotonic()
    context = ssl.create_default_context()
    with socket.create_connection((upstream["address"], upstream["port"]), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=upstream["sni"]) as conn:
            conn.settimeout(5)
            conn.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", recv_exact(conn, 2))[0]
            response = recv_exact(conn, length)
    if len(response) < 12 or response[:2] != packet[:2] or not response[2] & 0x80:
        raise ValueError("Invalid DNS response")
    return {
        "healthy": True,
        "latency": round((time.monotonic() - start) * 1000, 2),
        "rcode": response[3] & 15,
        "dnssec_authenticated": bool(response[3] & 0x20),
    }


def benchmark_upstreams(custom_upstreams: list[dict[str, Any]] | None = None, name: str = "cloudflare.com") -> list[dict[str, Any]]:
    candidates = [
        {"name": "Cloudflare DNS", "address": "1.1.1.1", "port": 853, "sni": "cloudflare-dns.com"},
        {"name": "Quad9 Security", "address": "9.9.9.9", "port": 853, "sni": "dns.quad9.net"},
        {"name": "Google Public DNS", "address": "8.8.8.8", "port": 853, "sni": "dns.google"},
        {"name": "AdGuard DNS", "address": "94.140.14.14", "port": 853, "sni": "dns.adguard-dns.com"},
        {"name": "Mullvad Privacy DNS", "address": "194.242.2.2", "port": 853, "sni": "dns.mullvad.net"},
    ]
    if custom_upstreams:
        for u in custom_upstreams:
            if u.get("enabled", True) and u.get("address"):
                candidates.append({
                    "name": u.get("name") or u["address"],
                    "address": u["address"],
                    "port": int(u.get("port", 853)),
                    "sni": u.get("sni") or u.get("tls_hostname") or u["address"],
                })

    def probe_one(target: dict[str, Any]) -> dict[str, Any]:
        try:
            res = probe_dot(target, name)
            return {
                "name": target["name"],
                "address": target["address"],
                "port": target.get("port", 853),
                "sni": target["sni"],
                "healthy": True,
                "latency": res["latency"],
                "dnssec": res.get("dnssec_authenticated", False),
                "error": "",
            }
        except Exception as exc:
            return {
                "name": target["name"],
                "address": target["address"],
                "port": target.get("port", 853),
                "sni": target["sni"],
                "healthy": False,
                "latency": 9999.0,
                "dnssec": False,
                "error": str(exc)[:200],
            }

    unique_candidates = {c["address"]: c for c in candidates}.values()
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(probe_one, c) for c in unique_candidates]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: (not x["healthy"], x["latency"]))
    return results
