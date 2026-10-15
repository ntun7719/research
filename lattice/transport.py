"""Bounded DNS over TLS transport with Android Private DNS pipelining, EDNS0 DO-bit fidelity, negative caching SOA, local LAN A/AAAA/CNAME/TXT/PTR synthesis, and FRP PROXY support."""
from __future__ import annotations

import collections
import concurrent.futures
import ipaddress
import os
import socket
import socketserver
import ssl
import struct
import threading
import time
from typing import Any


QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}


def _build_edns0_opt(do_bit: bool = False) -> bytes:
    """Build an RFC 6891 EDNS0 OPT pseudo-RR (payload 1232 bytes), echoing the DO bit (RFC 3225)."""
    ttl_flags = 0x00008000 if do_bit else 0x00000000
    return b"\x00" + struct.pack("!HHIH", 41, 1232, ttl_flags, 0)


EDNS0_OPT_RR = _build_edns0_opt(False)


def _encode_name(name: str) -> bytes:
    clean = name.strip().rstrip(".")
    if not clean:
        return b"\x00"
    labels = clean.encode("idna").split(b".")
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a potentially compressed DNS domain name from wire format."""
    labels: list[str] = []
    pos = offset
    jumped = False
    next_offset = offset
    visited: set[int] = set()
    while True:
        if pos >= len(packet):
            raise ValueError("Truncated DNS name")
        if pos in visited:
            raise ValueError("Compression pointer loop")
        visited.add(pos)
        length = packet[pos]
        if length == 0:
            if not jumped:
                next_offset = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if not jumped:
                next_offset = pos + 2
                jumped = True
            pos = pointer
            continue
        if (length & 0xC0) != 0 or length > 63 or pos + 1 + length > len(packet):
            raise ValueError("Invalid label length")
        label = packet[pos + 1 : pos + 1 + length].decode("ascii", "replace").lower()
        labels.append(label)
        pos += 1 + length
    return ".".join(labels), next_offset


def _parse_question_section(packet: bytes, allow_response: bool = False) -> tuple[str, int, int, bool, bool]:
    """Parse question section and detect whether request carries an EDNS0 OPT record and DO bit."""
    if len(packet) < 17:
        raise ValueError("Truncated DNS packet")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if not allow_response and ((flags & 0x8000) or qd != 1 or an or ns):
        raise ValueError("Only one standard DNS question is accepted")
    if qd < 1:
        raise ValueError("Missing DNS question")
    labels: list[str] = []
    pos = 12
    while True:
        if pos >= len(packet):
            raise ValueError("Truncated qname")
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(packet):
            raise ValueError("Invalid qname")
        try:
            label = packet[pos : pos + size].decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid label encoding") from exc
        labels.append(label)
        pos += size
    if pos + 4 > len(packet):
        raise ValueError("Truncated question")
    qtype, qclass = struct.unpack("!HH", packet[pos : pos + 4])
    if (qclass not in (1, 255) and not allow_response) or qtype in (251, 252):
        raise ValueError("Unsupported DNS class or transfer request")
    q_end = pos + 4
    has_opt = False
    do_bit = False
    if ar > 0 and len(packet) >= q_end + 11:
        tail = packet[q_end:]
        idx = tail.find(b"\x00\x00\x29")
        if idx != -1 and len(tail) >= idx + 11:
            has_opt = True
            opt_ttl = struct.unpack("!I", tail[idx + 5 : idx + 9])[0]
            do_bit = bool(opt_ttl & 0x8000)
    return ".".join(labels), qtype, q_end, has_opt, do_bit


def read_question(packet: bytes) -> tuple[str, int, int]:
    name, qtype, q_end, _, _ = _parse_question_section(packet, allow_response=False)
    return name, qtype, q_end


def decode_dns_answers(packet: bytes) -> list[dict[str, Any]]:
    """Decode answer RRs from a DNS response packet for diagnostics and UI inspection."""
    if len(packet) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack("!6H", packet[:12])
    pos = 12
    try:
        for _ in range(qd):
            _, pos = _decode_name(packet, pos)
            pos += 4
        answers: list[dict[str, Any]] = []
        for _ in range(an):
            if pos >= len(packet):
                break
            rr_name, pos = _decode_name(packet, pos)
            if pos + 10 > len(packet):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", packet[pos : pos + 10])
            pos += 10
            if pos + rdlen > len(packet):
                break
            rdata = packet[pos : pos + rdlen]
            pos += rdlen
            val = ""
            if rtype == 1 and rdlen == 4:
                val = str(ipaddress.IPv4Address(rdata))
            elif rtype == 28 and rdlen == 16:
                val = str(ipaddress.IPv6Address(rdata))
            elif rtype in (2, 5, 12):
                val, _ = _decode_name(packet, pos - rdlen)
            elif rtype == 15 and rdlen >= 3:
                pref = struct.unpack("!H", rdata[:2])[0]
                exch, _ = _decode_name(packet, pos - rdlen + 2)
                val = f"{pref} {exch}"
            elif rtype == 16:
                parts: list[str] = []
                idx = 0
                while idx < len(rdata):
                    tlen = rdata[idx]
                    idx += 1
                    parts.append(rdata[idx : idx + tlen].decode("utf-8", "replace"))
                    idx += tlen
                val = " ".join(parts)
            else:
                val = rdata.hex()
            answers.append({
                "name": rr_name or ".",
                "type": QTYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                "ttl": ttl,
                "data": val,
                "class": rclass,
            })
        return answers
    except Exception:
        return []


def _synthetic_soa(qname_present: bool, ttl: int = 60) -> bytes:
    """Build a compact RFC 2308 negative-caching SOA record so Android caches NXDOMAIN/NODATA."""
    owner = b"\xc0\x0c" if qname_present else b"\x00"
    rdata = b"\x00\x00" + struct.pack("!5I", 1, 3600, 600, 86400, ttl)
    return owner + struct.pack("!HHIH", 6, 1, ttl, len(rdata)) + rdata


def _response_flags(packet: bytes, rcode: int) -> int:
    """Construct DNS response flags preserving OPCODE, RD, and CD bits from the client query."""
    if len(packet) >= 4:
        req_flags = struct.unpack("!H", packet[2:4])[0]
        opcode_rd = req_flags & 0x7900
        cd_bit = req_flags & 0x0010
    else:
        opcode_rd = 0
        cd_bit = 0
    return 0x8080 | opcode_rd | cd_bit | (rcode & 15)


def error_response(packet: bytes, rcode: int) -> bytes:
    has_opt = False
    do_bit = False
    qname = ""
    try:
        qname, _, end, has_opt, do_bit = _parse_question_section(packet, allow_response=False)
        body = packet[12:end]
        qd = 1
    except Exception:
        body = b""
        qd = 0
        if len(packet) > 12 and b"\x00\x00\x29" in packet[12:]:
            has_opt = True
    ident = packet[:2].ljust(2, b"\0")
    flags = _response_flags(packet, rcode)
    authority = b""
    ns_count = 0
    if qd == 1 and rcode in (0, 3):
        authority = _synthetic_soa(bool(qname), ttl=60)
        ns_count = 1
    ar_count = 1 if has_opt else 0
    trailing = authority + (_build_edns0_opt(do_bit) if has_opt else b"")
    return ident + struct.pack("!5H", flags, qd, 0, ns_count, ar_count) + body + trailing


def rewrite_response(packet: bytes, qtype: int, address: str, ttl: int = 60) -> bytes:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return error_response(packet, 2)
    wanted = 1 if ip.version == 4 else 28
    qname, _, end, has_opt, do_bit = _parse_question_section(packet, allow_response=False)
    ident = packet[:2]
    flags = _response_flags(packet, 0)
    ar_count = 1 if has_opt else 0
    opt_tail = _build_edns0_opt(do_bit) if has_opt else b""
    if qtype != wanted and qtype != 255:
        soa = _synthetic_soa(bool(qname), ttl=ttl)
        return ident + struct.pack("!5H", flags, 1, 0, 1, ar_count) + packet[12:end] + soa + opt_tail
    packed = ip.packed
    owner = b"\xc0\x0c" if qname else b"\x00"
    answer = owner + struct.pack("!HHIH", wanted, 1, ttl, len(packed)) + packed
    return ident + struct.pack("!5H", flags, 1, 1, 0, ar_count) + packet[12:end] + answer + opt_tail


def synthesize_rr_response(packet: bytes, rtype: int, rdata: bytes, ttl: int = 300) -> bytes:
    """Synthesize a DNS response for arbitrary RR types (TXT, CNAME, PTR)."""
    qname, _, end, has_opt, do_bit = _parse_question_section(packet, allow_response=False)
    ident = packet[:2]
    flags = _response_flags(packet, 0)
    ar_count = 1 if has_opt else 0
    opt_tail = _build_edns0_opt(do_bit) if has_opt else b""
    owner = b"\xc0\x0c" if qname else b"\x00"
    answer = owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return ident + struct.pack("!5H", flags, 1, 1, 0, ar_count) + packet[12:end] + answer + opt_tail


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("Connection closed")
        data.extend(chunk)
    return bytes(data)


def forward_local(packet: bytes, port: int) -> bytes:
    if len(packet) <= 4096:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.settimeout(1.5)
                udp_sock.connect(("127.0.0.1", port))
                udp_sock.send(packet)
                resp = udp_sock.recv(4096)
                if len(resp) >= 12 and resp[:2] == packet[:2] and (resp[2] & 0x80) and not (resp[2] & 0x02):
                    return resp
        except (socket.timeout, OSError):
            pass

    with socket.create_connection(("127.0.0.1", port), timeout=4) as conn:
        conn.settimeout(4)
        conn.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", recv_exact(conn, 2))[0]
        if length < 12 or length > 65535:
            raise ValueError("Invalid resolver response length")
        result = recv_exact(conn, length)
    if result[:2] != packet[:2] or not result[2] & 0x80:
        raise ValueError("Resolver returned a mismatched response")
    return result


def forward_upstream_dot(packet: bytes, upstreams: list[dict[str, Any]], qname: str = "", routes: list[dict[str, Any]] | None = None) -> bytes:
    """Direct DoT upstream failover when local Unbound is reloading or unavailable."""
    enabled = {u["id"]: u for u in upstreams if u.get("enabled", True)}
    selected: list[dict[str, Any]] = []
    if qname and routes:
        clean_q = qname.lower().rstrip(".")
        for route in sorted(routes, key=lambda r: r["suffix"].count("."), reverse=True):
            sfx = route["suffix"].lower().rstrip(".")
            if clean_q == sfx or clean_q.endswith("." + sfx):
                selected = [enabled[uid] for uid in route.get("upstreams", []) if uid in enabled]
                if selected:
                    break
    if not selected:
        selected = list(enabled.values())
    if not selected:
        raise ValueError("No enabled DoT upstreams available")

    orig_id = packet[:2]
    out_id = os.urandom(2)
    out_pkt = out_id + packet[2:]

    context = ssl.create_default_context()
    last_exc: Exception | None = None
    for upstream in selected:
        try:
            with socket.create_connection((upstream["address"], int(upstream.get("port", 853))), timeout=3.5) as raw:
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sni = upstream.get("sni") or upstream.get("tls_hostname") or upstream["address"]
                with context.wrap_socket(raw, server_hostname=sni) as tls_conn:
                    tls_conn.settimeout(3.5)
                    tls_conn.sendall(struct.pack("!H", len(out_pkt)) + out_pkt)
                    length = struct.unpack("!H", recv_exact(tls_conn, 2))[0]
                    if 12 <= length <= 65535:
                        resp = recv_exact(tls_conn, length)
                        if resp[:2] == out_id and (resp[2] & 0x80):
                            return orig_id + resp[2:]
        except Exception as exc:
            last_exc = exc
            continue
    raise ValueError(f"All DoT upstreams failed: {last_exc}")


def read_proxy_line(sock: socket.socket) -> str:
    data = bytearray()
    while len(data) < 108:
        char = recv_exact(sock, 1)
        data.extend(char)
        if data.endswith(b"\r\n"):
            break
    if not data.endswith(b"\r\n"):
        raise ValueError("Invalid PROXY header")
    line = data.decode("ascii", "strict").strip()
    parts = line.split()
    if len(parts) >= 2 and parts[0] == "PROXY" and parts[1] == "UNKNOWN":
        return ""
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        raise ValueError("Invalid PROXY header")
    address = str(ipaddress.ip_address(parts[2]))
    int(parts[4])
    int(parts[5])
    return address


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


class DualStackTCPServer(ThreadedTCPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()


def _normalize_client_ip(addr: str) -> str:
    """Normalize IPv4-mapped IPv6 addresses (::ffff:192.0.2.1 -> 192.0.2.1) for policy matching."""
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return addr


class DNSGateway:
    def __init__(self, store, policy, certs, resolver_port: int = 5353, direct_port: int = 8853, frp_port: int = 8854):
        self.store = store
        self.policy = policy
        self.certs = certs
        self.resolver_port = resolver_port
        self.direct_port = direct_port
        self.frp_port = frp_port
        self.servers: list[ThreadedTCPServer] = []
        self.threads: list[threading.Thread] = []
        self.connection_slots = threading.BoundedSemaphore(256)
        self.pipeline_pool = concurrent.futures.ThreadPoolExecutor(max_workers=64, thread_name_prefix="dot-pipe")
        self.rate_lock = threading.Lock()
        self.rate: dict[str, tuple[int, int]] = {}
        self._last_rate_cleanup = 0.0
        self.metrics_lock = threading.Lock()
        self.metrics = collections.Counter()
        self.last_query = 0.0
        self.last_connection = 0.0

    def _limited(self, client: str, limit: int) -> bool:
        bucket = int(time.monotonic())
        with self.rate_lock:
            old_bucket, count = self.rate.get(client, (bucket, 0))
            count = count + 1 if old_bucket == bucket else 1
            self.rate[client] = (bucket, count)
            now = time.monotonic()
            if len(self.rate) > 10000 and (now - self._last_rate_cleanup > 5.0):
                self._last_rate_cleanup = now
                stale = [key for key, value in self.rate.items() if value[0] < bucket - 5]
                for key in stale[:2000]:
                    self.rate.pop(key, None)
        return count > limit

    def _resolve_local_record(self, packet: bytes, name: str, qtype: int) -> bytes | None:
        """Serve RFC 9462 DDR (_dns.resolver.arpa), localhost, and split-horizon LAN records (A, AAAA, CNAME, TXT, PTR)."""
        clean = name.lower().rstrip(".")
        if clean == "_dns.resolver.arpa":
            return error_response(packet, 0)
        if clean in ("localhost", "localhost.localdomain"):
            return rewrite_response(packet, qtype, "::1" if qtype == 28 else "127.0.0.1", ttl=300)
        if clean == "1.0.0.127.in-addr.arpa" and qtype in (12, 255):
            return synthesize_rr_response(packet, 12, _encode_name("localhost"), ttl=300)

        local_records = self.store.config.get("local_records", [])
        if qtype in (12, 255) and (clean.endswith(".in-addr.arpa") or clean.endswith(".ip6.arpa")):
            for rec in local_records:
                if rec["type"].upper() in ("A", "AAAA"):
                    try:
                        rev_ptr = ipaddress.ip_address(rec["value"]).reverse_pointer.lower().rstrip(".")
                        if rev_ptr == clean:
                            return synthesize_rr_response(packet, 12, _encode_name(rec["name"]), ttl=int(rec.get("ttl", 300)))
                    except ValueError:
                        pass

        matched = [r for r in local_records if r["name"].lower().rstrip(".") == clean]
        if not matched:
            return None

        # First check exact qtype match (or ANY=255)
        for rec in matched:
            rtype = rec["type"].upper()
            ttl = int(rec.get("ttl", 300))
            if rtype == "A" and qtype in (1, 255):
                return rewrite_response(packet, 1, rec["value"], ttl=ttl)
            if rtype == "AAAA" and qtype in (28, 255):
                return rewrite_response(packet, 28, rec["value"], ttl=ttl)
            if rtype == "CNAME" and qtype in (5, 1, 28, 255):
                return synthesize_rr_response(packet, 5, _encode_name(rec["value"]), ttl=ttl)
            if rtype == "TXT" and qtype in (16, 255):
                raw_txt = rec["value"].encode("utf-8")[:255]
                return synthesize_rr_response(packet, 16, bytes([len(raw_txt)]) + raw_txt, ttl=ttl)

        # Hostname exists in local_records, but requested type (e.g. HTTPS/65 or AAAA when only A exists) is absent -> NODATA + SOA
        return error_response(packet, 0)

    def _forward_query(self, packet: bytes, name: str, qtype: int) -> tuple[bytes, str]:
        """Serve local/DDR records immediately, then query local Unbound with Direct DoT Upstream failover."""
        local_ans = self._resolve_local_record(packet, name, qtype)
        if local_ans is not None:
            return local_ans, "local:record"
        try:
            resp = forward_local(packet, self.resolver_port)
            rcode = resp[3] & 15 if len(resp) >= 4 else 2
            if rcode != 2:
                return resp, ""
            try:
                cfg = self.store.config
                fallback = forward_upstream_dot(packet, cfg.get("upstreams", []), qname=name, routes=cfg.get("routes", []))
                return fallback, "failover:dot"
            except Exception:
                return resp, ""
        except Exception:
            cfg = self.store.config
            fallback = forward_upstream_dot(packet, cfg.get("upstreams", []), qname=name, routes=cfg.get("routes", []))
            return fallback, "failover:dot"

    def handle_query(self, packet: bytes, client: str, transport: str = "dot") -> bytes:
        return self._handle_query(packet, _normalize_client_ip(client), transport)

    def _handle_query(self, packet: bytes, client: str, transport: str) -> bytes:
        start = time.monotonic()
        try:
            name, qtype, _ = read_question(packet)
        except Exception:
            with self.metrics_lock:
                self.metrics["malformed"] += 1
            return error_response(packet, 1)

        profile_cfg = self.policy.profile(client)
        profile_id = profile_cfg["id"]
        action = "allowed"
        detail = ""
        try:
            if self._limited(client, profile_cfg["rate_limit"]):
                action = "refused"
                detail = "rate_limit"
                result = error_response(packet, 5)
            else:
                decision = self.policy.decide(client, name)
                detail = decision.source
                if decision.action == "deny":
                    action = "blocked"
                    mode = self.store.config.get("block_response", "nxdomain")
                    if mode == "zero":
                        if qtype == 28:
                            result = rewrite_response(packet, qtype, "::", ttl=30)
                        elif qtype in (1, 255):
                            result = rewrite_response(packet, qtype, "0.0.0.0", ttl=30)
                        else:
                            result = error_response(packet, 0)
                    elif mode == "refused":
                        result = error_response(packet, 5)
                    else:
                        result = error_response(packet, 3)
                elif decision.action == "rewrite":
                    action = "rewritten"
                    result = rewrite_response(packet, qtype, decision.value)
                else:
                    result, fb_note = self._forward_query(packet, name, qtype)
                    if fb_note:
                        detail = f"{detail} ({fb_note})" if detail else fb_note
        except Exception:
            action = "error"
            detail = "resolver_failure"
            result = error_response(packet, 2)

        latency = (time.monotonic() - start) * 1000
        rcode = result[3] & 15 if len(result) >= 4 else 2
        with self.metrics_lock:
            self.metrics["queries"] += 1
            self.metrics[action] += 1
            self.metrics[transport + "_queries"] += 1
            self.last_query = time.time()
        self.store.log_query(client, name, qtype, action, profile_id, latency, rcode, detail)
        return result

    def _handler(self, bridge: bool):
        gateway = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                if not gateway.connection_slots.acquire(blocking=False):
                    with gateway.metrics_lock:
                        gateway.metrics["rejected_connections"] += 1
                    try:
                        self.request.close()
                    except Exception:
                        pass
                    return
                try:
                    raw: socket.socket = self.request
                    for opt_level, opt_name in (
                        (socket.IPPROTO_TCP, socket.TCP_NODELAY),
                        (socket.SOL_SOCKET, socket.SO_KEEPALIVE),
                    ):
                        try:
                            raw.setsockopt(opt_level, opt_name, 1)
                        except OSError:
                            pass
                    raw.settimeout(10)
                    client = _normalize_client_ip(self.client_address[0])
                    if bridge:
                        proxied = read_proxy_line(raw)
                        if proxied:
                            client = _normalize_client_ip(proxied)
                    context = gateway.certs.context
                    if context is None:
                        with gateway.metrics_lock:
                            gateway.metrics["tls_unavailable"] += 1
                        return
                    with context.wrap_socket(raw, server_side=True) as conn:
                        conn.settimeout(65)
                        with gateway.metrics_lock:
                            gateway.metrics["connections"] += 1
                            gateway.metrics["frp_connections" if bridge else "direct_connections"] += 1
                            gateway.last_connection = time.time()

                        send_lock = threading.Lock()
                        inflight = threading.BoundedSemaphore(16)
                        active_futures: list[concurrent.futures.Future] = []
                        transport_kind = "frp" if bridge else "direct"

                        def process_and_send(pkt: bytes) -> None:
                            try:
                                resp = gateway._handle_query(pkt, client, transport_kind)
                                framed = struct.pack("!H", len(resp)) + resp
                                with send_lock:
                                    conn.sendall(framed)
                            except (OSError, ssl.SSLError):
                                pass
                            finally:
                                inflight.release()

                        while True:
                            try:
                                length_bytes = recv_exact(conn, 2)
                            except (OSError, socket.timeout, ssl.SSLError):
                                break
                            length = struct.unpack("!H", length_bytes)[0]
                            if length < 12 or length > 4096:
                                break
                            try:
                                packet = recv_exact(conn, length)
                            except (OSError, socket.timeout, ssl.SSLError):
                                break
                            if not inflight.acquire(timeout=5.0):
                                break
                            try:
                                fut = gateway.pipeline_pool.submit(process_and_send, packet)
                                active_futures.append(fut)
                                if len(active_futures) > 32:
                                    active_futures = [f for f in active_futures if not f.done()]
                            except RuntimeError:
                                inflight.release()
                                process_and_send(packet)

                        for fut in active_futures:
                            try:
                                fut.result(timeout=4.0)
                            except Exception:
                                pass
                except (OSError, ValueError, ssl.SSLError):
                    with gateway.metrics_lock:
                        gateway.metrics["handshake_failures"] += 1
                finally:
                    gateway.connection_slots.release()

        return Handler

    def start(self) -> None:
        if self.servers:
            return
        try:
            direct: ThreadedTCPServer = DualStackTCPServer(("::", self.direct_port), self._handler(False))
        except OSError:
            direct = ThreadedTCPServer(("0.0.0.0", self.direct_port), self._handler(False))
        bridge = ThreadedTCPServer(("127.0.0.1", self.frp_port), self._handler(True))
        self.servers = [direct, bridge]
        for server, label in ((direct, "dot-direct"), (bridge, "dot-frp")):
            thread = threading.Thread(target=server.serve_forever, name=label, daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()
        self.threads.clear()

    def status(self) -> dict[str, Any]:
        with self.metrics_lock:
            metrics = dict(self.metrics)
            last_query = self.last_query
            last_connection = self.last_connection
        return {
            "running": bool(self.servers),
            "certificate_ready": self.certs.context is not None,
            "direct_port": self.direct_port,
            "frp_local_port": self.frp_port,
            "last_query": last_query,
            "last_connection": last_connection,
            "metrics": metrics,
            "pipelining": True,
            "edns0_compliant": True,
        }
