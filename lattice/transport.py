"""Bounded DNS over TLS transport with L1 wire cache, CNAME cloaking protection, Android Private DNS pipelining, EDNS0 DO-bit fidelity, negative caching SOA, local LAN synthesis, and FRP PROXY v1/v2 support."""
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


from .policy import is_android_essential

FALLBACK_CONNECTIVITY_IPS: dict[str, tuple[str, str]] = {
    "connectivitycheck.gstatic.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "connectivitycheck.android.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "www.gstatic.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "ssl.gstatic.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "metric.gstatic.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "dnsotls-ds.metric.gstatic.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "android.clients.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients1.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients2.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients3.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients4.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients5.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "clients6.google.com": ("142.250.190.14", "2607:f8b0:4005:801::200e"),
    "cp.cloudflare.com": ("104.16.132.229", "2606:4700::6810:84e5"),
    "connectivity.cloudflareclient.com": ("104.16.132.229", "2606:4700::6810:84e5"),
    "engage.cloudflareclient.com": ("162.159.192.1", "2606:4700:d0::a29f:c001"),
    "captive.apple.com": ("17.253.144.10", "2620:149:a44::10"),
    "www.msftconnecttest.com": ("13.107.4.52", "2a01:111:2003::52"),
    "dns.msftncsi.com": ("131.107.255.255", "fd3e:4f5a:5b81::1"),
    "www.msftncsi.com": ("131.107.255.255", "fd3e:4f5a:5b81::1"),
}

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
    """Decode answer RRs from a DNS response packet for diagnostics, CNAME cloaking, and UI inspection."""
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
                "rtype": rtype,
                "ttl": ttl,
                "data": val,
                "class": rclass,
            })
        return answers
    except Exception:
        return []


class DNSCache:
    """Thread-safe L1 wire-speed DNS response cache with RFC 8767 serve-expired support."""

    def __init__(self, max_entries: int = 8192):
        self.max_entries = max_entries
        self.lock = threading.Lock()
        self.entries: collections.OrderedDict[tuple[str, int, bool], dict[str, Any]] = collections.OrderedDict()
        self.hits = 0
        self.misses = 0
        self.stale_hits = 0
        self.prefetches = 0

    @staticmethod
    def _patch_wire_ttl(wire_body: bytes, new_ttl: int) -> bytes:
        """Dynamically rewrite Answer RR TTLs in a cached DNS wire body (excluding 2-byte txid)."""
        packet = b"\x00\x00" + wire_body
        if len(packet) < 12:
            return wire_body
        _, _, qd, an, _, _ = struct.unpack("!6H", packet[:12])
        if an == 0:
            return wire_body
        buf = bytearray(packet)
        pos = 12
        try:
            for _ in range(qd):
                _, pos = _decode_name(packet, pos)
                pos += 4
            for _ in range(an):
                if pos >= len(packet):
                    break
                _, pos = _decode_name(packet, pos)
                if pos + 10 > len(packet):
                    break
                _, _, _, rdlen = struct.unpack("!HHIH", packet[pos : pos + 10])
                buf[pos + 4 : pos + 8] = struct.pack("!I", max(1, int(new_ttl)))
                pos += 10 + rdlen
            return bytes(buf[2:])
        except Exception:
            return wire_body

    def get(self, qname: str, qtype: int, do_bit: bool, ident: bytes, allow_stale: bool = False) -> bytes | None:
        key = (qname.lower().rstrip("."), qtype, do_bit)
        now = time.time()
        with self.lock:
            item = self.entries.get(key)
            if not item:
                self.misses += 1
                return None
            if now <= item["expires_at"]:
                self.entries.move_to_end(key)
                self.hits += 1
                item["hits"] += 1
                rem_ttl = max(1, int(item["expires_at"] - now))
                return ident + self._patch_wire_ttl(item["wire_body"], rem_ttl)
            if allow_stale and now <= item["stale_until"]:
                self.entries.move_to_end(key)
                self.stale_hits += 1
                item["hits"] += 1
                return ident + self._patch_wire_ttl(item["wire_body"], 30)
            self.entries.pop(key, None)
            self.misses += 1
            return None

    def evict(self, domain: str) -> int:
        clean = domain.lower().rstrip(".")
        with self.lock:
            keys = [k for k in self.entries if k[0] == clean]
            for k in keys:
                self.entries.pop(k, None)
            return len(keys)

    def put(self, qname: str, qtype: int, do_bit: bool, response: bytes, serve_expired_ttl: int = 3600) -> None:
        if len(response) < 12:
            return
        rcode = response[3] & 15
        if rcode not in (0, 3):
            return
        decoded = decode_dns_answers(response)
        if decoded:
            min_ttl = max(15, min(3600, min(int(r.get("ttl", 60)) for r in decoded)))
            summary = ", ".join(f"{r['type']} {r['data']}" for r in decoded[:3])
        else:
            min_ttl = 60
            summary = "NXDOMAIN" if rcode == 3 else "NODATA"
        now = time.time()
        key = (qname.lower().rstrip("."), qtype, do_bit)
        entry = {
            "domain": key[0] or ".",
            "qtype": qtype,
            "qtype_name": QTYPE_NAMES.get(qtype, f"TYPE{qtype}"),
            "rcode": rcode,
            "summary": summary,
            "wire_body": response[2:],
            "stored_at": now,
            "expires_at": now + min_ttl,
            "stale_until": now + min_ttl + max(60, serve_expired_ttl),
            "ttl": min_ttl,
            "hits": 0,
        }
        with self.lock:
            self.entries[key] = entry
            self.entries.move_to_end(key)
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)

    def clear(self) -> int:
        with self.lock:
            count = len(self.entries)
            self.entries.clear()
            return count

    def stats(self) -> dict[str, Any]:
        now = time.time()
        with self.lock:
            active_items = []
            for item in reversed(list(self.entries.values())):
                rem = int(item["expires_at"] - now)
                if rem > -3600:
                    active_items.append({
                        "domain": item["domain"],
                        "type": item["qtype_name"],
                        "summary": item["summary"],
                        "ttl_remaining": max(0, rem),
                        "stale": rem <= 0,
                        "hits": item["hits"],
                    })
                if len(active_items) >= 25:
                    break
            total_lookups = self.hits + self.stale_hits + self.misses
            hit_rate = round(((self.hits + self.stale_hits) / total_lookups) * 100, 1) if total_lookups else 0.0
            return {
                "entries": len(self.entries),
                "active_entries": len(self.entries),
                "size": len(self.entries),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "stale_hits": self.stale_hits,
                "misses": self.misses,
                "prefetches": self.prefetches,
                "hit_rate_pct": hit_rate,
                "hit_rate": hit_rate,
                "top_entries": active_items,
            }

    def expiring_hot_candidates(self, now: float | None = None, limit: int = 8) -> list[tuple[str, int, bool]]:
        now_ts = now if now is not None else time.time()
        candidates: list[tuple[int, tuple[str, int, bool]]] = []
        with self.lock:
            for key, item in self.entries.items():
                if item.get("hits", 0) < 1:
                    continue
                rem = item["expires_at"] - now_ts
                threshold = max(15.0, float(item.get("ttl", 60)) * 0.25)
                if -300.0 <= rem <= threshold and (now_ts - item.get("last_prefetch", 0.0)) > 20.0:
                    item["last_prefetch"] = now_ts
                    candidates.append((int(item["hits"]), key))
        candidates.sort(key=lambda x: x[0], reverse=True)
        return [k for _, k in candidates[:limit]]


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
    truncated = False
    if len(packet) <= 4096:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.settimeout(1.1)
                udp_sock.connect(("127.0.0.1", port))
                udp_sock.send(packet)
                resp = udp_sock.recv(4096)
                if len(resp) >= 12 and resp[:2] == packet[:2] and (resp[2] & 0x80):
                    if not (resp[2] & 0x02):
                        return resp
                    truncated = True
        except socket.timeout as exc:
            raise TimeoutError("Local Unbound UDP timeout") from exc
        except OSError:
            pass
    else:
        truncated = True

    if not truncated:
        raise OSError("Local Unbound UDP unreachable")

    with socket.create_connection(("127.0.0.1", port), timeout=1.5) as conn:
        conn.settimeout(1.5)
        conn.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", recv_exact(conn, 2))[0]
        if length < 12 or length > 65535:
            raise ValueError("Invalid resolver response length")
        result = recv_exact(conn, length)
    if result[:2] != packet[:2] or not result[2] & 0x80:
        raise ValueError("Resolver returned a mismatched response")
    return result


_TEST_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def is_rebinding_ip(ip_str: str) -> bool:
    """Return True if an upstream DNS answer IP is RFC 1918 private, loopback, link-local, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    if any(ip in net for net in _TEST_DOC_NETS):
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)


class UpstreamTLSPool:
    """Thread-safe TLS 1.3 keep-alive socket pool and EWMA latency tracker for DoT upstreams."""

    def __init__(self, max_idle: float = 45.0):
        self.max_idle = max_idle
        self.lock = threading.Lock()
        self.pool: dict[tuple[str, int, str], list[tuple[ssl.SSLSocket, float]]] = collections.defaultdict(list)
        self.latencies: dict[str, float] = {}
        self.pool_hits = 0
        self.pool_misses = 0
        self.context = ssl.create_default_context()

    def _borrow(self, key: tuple[str, int, str]) -> ssl.SSLSocket | None:
        now = time.monotonic()
        with self.lock:
            items = self.pool.get(key, [])
            while items:
                conn, ts = items.pop()
                if now - ts <= self.max_idle:
                    self.pool_hits += 1
                    return conn
                try:
                    conn.close()
                except Exception:
                    pass
            self.pool_misses += 1
            return None

    def _release(self, key: tuple[str, int, str], conn: ssl.SSLSocket) -> None:
        now = time.monotonic()
        with self.lock:
            bucket = self.pool[key]
            if len(bucket) >= 4:
                old_conn, _ = bucket.pop(0)
                try:
                    old_conn.close()
                except Exception:
                    pass
            bucket.append((conn, now))

    def record_latency(self, uid: str, ms: float) -> None:
        with self.lock:
            prev = self.latencies.get(uid)
            self.latencies[uid] = round(ms if prev is None else (prev * 0.7 + ms * 0.3), 2)

    def clear(self) -> int:
        with self.lock:
            closed = 0
            for bucket in self.pool.values():
                while bucket:
                    conn, _ = bucket.pop()
                    closed += 1
                    try:
                        conn.close()
                    except Exception:
                        pass
            self.pool.clear()
            return closed

    def query(self, upstream: dict[str, Any], out_pkt: bytes) -> bytes:
        addr = upstream["address"]
        port = int(upstream.get("port", 853))
        sni = upstream.get("sni") or upstream.get("tls_hostname") or addr
        uid = upstream.get("id", addr)
        key = (addr, port, sni)
        framed = struct.pack("!H", len(out_pkt)) + out_pkt
        t0 = time.monotonic()

        conn = self._borrow(key)
        if conn is not None:
            try:
                conn.settimeout(1.5)
                conn.sendall(framed)
                length = struct.unpack("!H", recv_exact(conn, 2))[0]
                if 12 <= length <= 65535:
                    resp = recv_exact(conn, length)
                    self._release(key, conn)
                    self.record_latency(uid, (time.monotonic() - t0) * 1000.0)
                    return resp
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

        t0 = time.monotonic()
        raw = socket.create_connection((addr, port), timeout=2.2)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tls_conn = self.context.wrap_socket(raw, server_hostname=sni)
        try:
            tls_conn.settimeout(2.2)
            tls_conn.sendall(framed)
            length = struct.unpack("!H", recv_exact(tls_conn, 2))[0]
            if not (12 <= length <= 65535):
                raise ValueError("Invalid DoT upstream response length")
            resp = recv_exact(tls_conn, length)
            self._release(key, tls_conn)
            self.record_latency(uid, (time.monotonic() - t0) * 1000.0)
            return resp
        except Exception:
            try:
                tls_conn.close()
            except Exception:
                pass
            raise

    def stats(self) -> dict[str, Any]:
        with self.lock:
            active_sockets = sum(len(v) for v in self.pool.values())
            return {
                "active_sockets": active_sockets,
                "pool_hits": self.pool_hits,
                "pool_misses": self.pool_misses,
                "ewma_latencies_ms": dict(self.latencies),
            }


UPSTREAM_TLS_POOL = UpstreamTLSPool()


def forward_upstream_dot(packet: bytes, upstreams: list[dict[str, Any]], qname: str = "", routes: list[dict[str, Any]] | None = None) -> bytes:
    """Direct DoT upstream failover with TLS 1.3 keep-alive pooling and lowest-EWMA latency routing."""
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

    with UPSTREAM_TLS_POOL.lock:
        lat_map = dict(UPSTREAM_TLS_POOL.latencies)
    selected.sort(key=lambda u: lat_map.get(u.get("id", u["address"]), 50.0))

    orig_id = packet[:2]
    out_id = os.urandom(2)
    out_pkt = out_id + packet[2:]

    last_exc: Exception | None = None
    for upstream in selected:
        try:
            resp = UPSTREAM_TLS_POOL.query(upstream, out_pkt)
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


PROXY_V2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"


def peek_and_read_proxy(sock: socket.socket) -> str:
    """MTU-safe non-destructive socket peek: instant return on TLS 0x16 ClientHello, fragment-safe for PROXY v1/v2."""
    try:
        first = sock.recv(1, socket.MSG_PEEK)
    except OSError:
        return ""
    if not first or first[0] == 0x16:
        # 0x16 is standard TLS Handshake record type (ClientHello) — return immediately!
        return ""
    if first[0] == 0x50:  # "P" -> PROXY v1
        return read_proxy_line(sock)
    if first[0] == 0x0D:  # "\r" -> PROXY v2 binary signature
        try:
            peek12 = sock.recv(12, socket.MSG_PEEK)
            if peek12 == PROXY_V2_SIG:
                header = recv_exact(sock, 16)
                ver_cmd = header[12]
                fam_proto = header[13]
                addr_len = struct.unpack("!H", header[14:16])[0]
                payload = recv_exact(sock, addr_len) if addr_len > 0 else b""
                if (ver_cmd & 0x0F) == 0x01:
                    if (fam_proto & 0xF0) == 0x10 and len(payload) >= 12:
                        return str(ipaddress.IPv4Address(payload[:4]))
                    if (fam_proto & 0xF0) == 0x20 and len(payload) >= 36:
                        return str(ipaddress.IPv6Address(payload[:16]))
        except OSError:
            return ""
    return ""


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
        self.cache = DNSCache(max_entries=8192)
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
        clean = name.lower().rstrip(".")
        if clean == "_dns.resolver.arpa":
            return error_response(packet, 0)
        if clean == "ipv4only.arpa":
            if qtype in (1, 255):
                return rewrite_response(packet, 1, "192.0.0.170", ttl=300)
            return error_response(packet, 0)
        if clean == "dnsotls-ds.metric.gstatic.com" or clean.endswith(".dnsotls-ds.metric.gstatic.com"):
            # Instant <0.1ms synthesis for Android DnsTlsTransport random-UUID DoT probes during VPN switches
            if qtype in (1, 255):
                return rewrite_response(packet, 1, "142.250.190.14", ttl=60)
            if qtype == 28:
                return rewrite_response(packet, 28, "2607:f8b0:4005:801::200e", ttl=60)
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

        return error_response(packet, 0)

    def _forward_query(self, packet: bytes, name: str, qtype: int) -> tuple[bytes, str]:
        """Serve L1 wire cache and local/DDR records immediately, then query Unbound with Direct DoT failover."""
        _, _, _, _, do_bit = _parse_question_section(packet, allow_response=False)
        cached = self.cache.get(name, qtype, do_bit, packet[:2], allow_stale=False)
        if cached is not None:
            with self.metrics_lock:
                self.metrics["cache_hits"] += 1
            return cached, "cache:l1"

        local_ans = self._resolve_local_record(packet, name, qtype)
        if local_ans is not None:
            if name.lower().rstrip(".") != "_dns.resolver.arpa":
                self.cache.put(name, qtype, do_bit, local_ans, serve_expired_ttl=3600)
            return local_ans, "local:record"

        cache_cfg = self.store.config.get("cache", {})
        serve_expired = bool(cache_cfg.get("serve_expired", True))
        stale_ttl = int(cache_cfg.get("serve_expired_ttl", 3600))

        try:
            resp = forward_local(packet, self.resolver_port)
            rcode = resp[3] & 15 if len(resp) >= 4 else 2
            if rcode != 2:
                self.cache.put(name, qtype, do_bit, resp, serve_expired_ttl=stale_ttl)
                return resp, ""
            try:
                cfg = self.store.config
                fallback = forward_upstream_dot(packet, cfg.get("upstreams", []), qname=name, routes=cfg.get("routes", []))
                self.cache.put(name, qtype, do_bit, fallback, serve_expired_ttl=stale_ttl)
                return fallback, "failover:dot"
            except Exception:
                if serve_expired:
                    stale = self.cache.get(name, qtype, do_bit, packet[:2], allow_stale=True)
                    if stale is not None:
                        return stale, "cache:stale"
                return resp, ""
        except Exception:
            try:
                cfg = self.store.config
                fallback = forward_upstream_dot(packet, cfg.get("upstreams", []), qname=name, routes=cfg.get("routes", []))
                self.cache.put(name, qtype, do_bit, fallback, serve_expired_ttl=stale_ttl)
                return fallback, "failover:dot"
            except Exception:
                if serve_expired:
                    stale = self.cache.get(name, qtype, do_bit, packet[:2], allow_stale=True)
                    if stale is not None:
                        return stale, "cache:stale"
                clean_q = name.lower().rstrip(".")
                fb_ips = FALLBACK_CONNECTIVITY_IPS.get(clean_q)
                if fb_ips or is_android_essential(clean_q, self.store.config.get("hostname", "")):
                    v4_ip, v6_ip = fb_ips or ("142.250.190.14", "2607:f8b0:4005:801::200e")
                    if qtype in (1, 255):
                        return rewrite_response(packet, 1, v4_ip, ttl=30), "vpn:probe-rescue"
                    if qtype == 28:
                        return rewrite_response(packet, 28, v6_ip, ttl=30), "vpn:probe-rescue"
                    return error_response(packet, 0), "vpn:probe-rescue"
                raise

    def _block_packet(self, packet: bytes, qtype: int) -> bytes:
        mode = self.store.config.get("block_response", "nxdomain")
        ttl = int(self.store.config.get("block_ttl", 30) or 30)
        if mode == "custom_ip":
            custom_ip = self.store.config.get("block_custom_ip", "") or "0.0.0.0"
            return rewrite_response(packet, qtype, custom_ip, ttl=ttl)
        if mode == "zero":
            if qtype == 28:
                return rewrite_response(packet, qtype, "::", ttl=ttl)
            if qtype in (1, 255):
                return rewrite_response(packet, qtype, "0.0.0.0", ttl=ttl)
            return error_response(packet, 0)
        if mode == "refused":
            return error_response(packet, 5)
        return error_response(packet, 3)

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
            is_probe = is_android_essential(name, self.store.config.get("hostname", ""))
            if not is_probe and client not in ("127.0.0.1", "::1") and self._limited(client, max(profile_cfg["rate_limit"], 600)):
                action = "refused"
                detail = "rate_limit"
                result = error_response(packet, 5)
            else:
                decision = self.policy.decide(client, name)
                detail = decision.source
                if decision.action == "deny":
                    action = "blocked"
                    result = self._block_packet(packet, qtype)
                elif decision.action == "rewrite":
                    action = "rewritten"
                    result = rewrite_response(packet, qtype, decision.value)
                else:
                    result, fb_note = self._forward_query(packet, name, qtype)
                    if fb_note:
                        detail = f"{detail} ({fb_note})" if detail else fb_note
                    # CNAME Cloaking & DNS Rebinding Inspection
                    if (result[3] & 15) == 0 and not self.store.is_blocking_paused():
                        decoded_answers = decode_dns_answers(result)
                        for ans in decoded_answers:
                            if ans.get("rtype") == 5 and ans.get("data"):
                                cname_target_name = str(ans["data"]).strip().rstrip(".")
                                cname_dec = self.policy.decide(client, cname_target_name)
                                if cname_dec.action == "deny":
                                    action = "blocked"
                                    detail = f"cname_cloak:{cname_target_name} ({cname_dec.source})"
                                    result = self._block_packet(packet, qtype)
                                    self.cache.evict(name)
                                    break
                        if action == "allowed" and fb_note != "local:record" and self.store.config.get("rebinding_protection", True):
                            clean_q = name.lower().rstrip(".")
                            local_names = {r["name"].lower().rstrip(".") for r in self.store.config.get("local_records", [])}
                            is_local_domain = (
                                clean_q in ("localhost", "localhost.localdomain")
                                or clean_q in local_names
                                or clean_q.endswith((".local", ".lan", ".home.arpa", ".internal", ".in-addr.arpa", ".ip6.arpa"))
                            )
                            if not is_local_domain:
                                for ans in decoded_answers:
                                    if ans.get("rtype") in (1, 28) and ans.get("data") and is_rebinding_ip(str(ans["data"])):
                                        action = "blocked"
                                        detail = f"security:dns-rebinding ({ans['data']})"
                                        result = self._block_packet(packet, qtype)
                                        self.cache.evict(clean_q)
                                        with self.metrics_lock:
                                            self.metrics["rebinding_blocked"] += 1
                                        break
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
                    for opt_level, opt_name, opt_val in (
                        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPIDLE", 4), 15),
                        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPINTVL", 5), 5),
                        (socket.IPPROTO_TCP, getattr(socket, "TCP_KEEPCNT", 6), 3),
                    ):
                        try:
                            raw.setsockopt(opt_level, opt_name, opt_val)
                        except OSError:
                            pass
                    raw.settimeout(10)
                    client = _normalize_client_ip(self.client_address[0])
                    proxied = peek_and_read_proxy(raw)
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

    def prefetch_hot_domains(self) -> dict[str, Any]:
        """Proactively refresh popular L1 cache entries whose TTL is nearing expiration."""
        cache_cfg = self.store.config.get("cache", {})
        if not cache_cfg.get("prefetch", True):
            return {"prefetched": 0, "candidates": 0}
        candidates = self.cache.expiring_hot_candidates(limit=8)
        prefetched = 0
        stale_ttl = int(cache_cfg.get("serve_expired_ttl", 3600))
        for domain, qtype, do_bit in candidates:
            try:
                q_pkt = struct.pack("!6H", 0x5052, 0x0100, 1, 0, 0, 1) + _encode_name(domain) + struct.pack("!HH", qtype, 1) + _build_edns0_opt(do_bit)
                try:
                    resp = forward_local(q_pkt, self.resolver_port)
                    if (resp[3] & 15) == 2:
                        raise ValueError("SERVFAIL")
                except Exception:
                    cfg = self.store.config
                    resp = forward_upstream_dot(q_pkt, cfg.get("upstreams", []), qname=domain, routes=cfg.get("routes", []))
                with self.cache.lock:
                    old_hits = self.cache.entries.get((domain, qtype, do_bit), {}).get("hits", 1)
                self.cache.put(domain, qtype, do_bit, resp, serve_expired_ttl=stale_ttl)
                with self.cache.lock:
                    if (domain, qtype, do_bit) in self.cache.entries:
                        self.cache.entries[(domain, qtype, do_bit)]["hits"] = old_hits
                        self.cache.entries[(domain, qtype, do_bit)]["last_prefetch"] = time.time()
                    self.cache.prefetches += 1
                prefetched += 1
            except Exception:
                continue
        return {"prefetched": prefetched, "candidates": len(candidates)}

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
            "l1_cache": self.cache.stats(),
            "cache": self.cache.stats(),
            "tls_pool": UPSTREAM_TLS_POOL.stats(),
            "pipelining": True,
            "edns0_compliant": True,
            "cname_cloaking_protection": True,
            "rebinding_protection": bool(self.store.config.get("rebinding_protection", True)),
        }
