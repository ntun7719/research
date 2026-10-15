# Lattice DNS — Gemini Edition (`v4.0.0-gemini`)

Lattice DNS is a high-assurance DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) control plane and telemetry dashboard engineered from scratch by **Gemini**. Built for Android Private DNS (`TCP/853`, `DnsTlsTransport` / `DnsTlsSocket`), Apple `.mobileconfig` profiles, encrypted upstream resolution, deterministic client policy routing, compact Bloom + SQLite subscription indexing, and zero-trust FRP remote tunneling with PROXY protocol v1 client IP preservation.

## Architecture & Android Private DNS Highlights (`v4.0.0-gemini`)

1. **Android `DnsTlsSocket` Concurrent Pipelining & Transport Layer (`lattice/transport.py`)**:
   - Dual-stack IPv4/IPv6 DoT listener (`TCP/8853`, mapped to host `853`) with RFC 8310 ALPN `"dot"`, `SO_KEEPALIVE`, and 65s idle session persistence.
   - **RFC 7766 / RFC 7858 Concurrent Pipelined Multiplexing**: Dispatches pipelined queries concurrently per TLS connection with a per-socket write lock so slow upstream lookups never cause Head-of-Line (HoL) blocking on Android validation bursts.
   - **RFC 6891 EDNS0 `OPT` (`DO`-Bit Echo) & RFC 2308 Negative-Caching `SOA`**: Preserves `OPCODE`, `RD`, `CD`, and `DO` bits and attaches compliant `OPT` (`ARCOUNT=1`) and negative-caching `SOA` (`NSCOUNT=1, TTL=60s`) records on synthesized `NXDOMAIN`/`NODATA` responses.
   - **Full Split-Horizon LAN Synthesis (`A`, `AAAA`, `CNAME`, `TXT`, and Reverse `PTR`)**: Serves dual-stack LAN records without type shadowing, plus RFC 9462 `_dns.resolver.arpa` (DDR) and `localhost` in `<0.1 ms`.
2. **Non-Blocking Telemetry & Deterministic Policy Engine (`lattice/policy.py` & `lattice/store.py`)**:
   - **Per-Device Client Profile Overrides**: Assign individual devices in the Device Registry to custom profiles (`kids`, `iot`, `vip`) overriding CIDR subnet defaults in real time.
   - **Zero-Stall Query Logging & In-Memory Feed Match Cache**: Buffers query telemetry in memory whenever SQLite is busy syncing multi-hundred-thousand-domain blocklists, eliminating DNS latency spikes during feed updates.
   - **SafeSearch & Android Probe Isolation**: Rewrites Google Search (`google.<tld>`, `www.google.<tld>`), YouTube, Bing, DuckDuckGo, and Yandex without hijacking Android system domains (`clients3.google.com`, `play.google.com`, `mtalk.google.com`, `dl.google.com`, `accounts.google.com`) and protects `connectivitycheck.gstatic.com`, `*.dnsotls-ds.metric.gstatic.com`, and `ipv4only.arpa`.
3. **Validating Recursive Forwarder (`lattice/resolver.py`)**:
   - Manages local `Unbound` with DNSSEC root trust anchor validation (`root.key` or IANA DS `20326` fallback), smart IPv6 upstream socket detection (`do-ip6: no` inside IPv4-only Docker networks), anti-blackhole DoT tuning (`infra-host-ttl: 15`, `infra-keep-probing: yes`), and automatic zero-downtime Direct DoT Upstream Failover (`forward_upstream_dot`) with outbound Transaction ID randomization.
4. **Gemini Cyber-Telemetry Control Plane (`lattice/static/`)**:
   - Obsidian & Emerald/Teal dark mode (`#070b12`) and Nordic Alabaster light mode (`#f8fafc`) with zero inline `style="..."` attributes (strict CSP compliance).
   - **Live Android Private DNS Readiness Doctor (`GET /api/diagnostics/android`)** and **1-Click SAN-Matched Self-Signed Certificate Generator (`POST /api/tls/self-signed`)**.
   - **Top Client Endpoints** & **Query Record Type Distribution** SVG telemetry cards, interactive Packet Forensics Drawer, and full RDATA answer decoding in the Diagnostic Simulator.

## Verification

```bash
PYTHONPATH=. python3 tests/test_core.py -v
node --check lattice/static/app.js
```
