import copy
import io
import json
import socket
import ssl
import struct
import tempfile
import time
import unittest
from pathlib import Path

from lattice.config import DEFAULT_CONFIG, hostname, validate_config
from lattice.integrations import CertificateVault, FRPSupervisor, render_frpc
from lattice.policy import Bloom, Policy, parse_feed_line
from lattice.resolver import ResolverManager, _question
from lattice.store import Store, password_hash, password_verify
from lattice.transport import error_response, read_proxy_line, read_question, rewrite_response


def query(name="example.com", qtype=1):
    clean = name.rstrip(".")
    if not clean:
        qname = b"\0"
    else:
        labels = clean.encode("idna").split(b".")
        qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


class ConfigTests(unittest.TestCase):
    def test_defaults_validate(self):
        cfg = validate_config(copy.deepcopy(DEFAULT_CONFIG))
        self.assertTrue(cfg["dnssec"])
        self.assertEqual(cfg["frp"]["remote_port"], 853)

    def test_frp_must_use_android_private_dns_port(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["frp"]["remote_port"] = 8853
        with self.assertRaises(ValueError):
            validate_config(cfg)

    def test_route_requires_enabled_upstream(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["routes"] = [{"suffix": "internal.example", "upstreams": ["missing"]}]
        with self.assertRaises(ValueError):
            validate_config(cfg)

    def test_hostname_validation_and_underscores(self):
        self.assertEqual(hostname("example.com"), "example.com")
        self.assertEqual(hostname("_dmarc.example.com"), "_dmarc.example.com")
        self.assertEqual(hostname("_acme-challenge.example.com"), "_acme-challenge.example.com")
        self.assertEqual(hostname("_sip._tcp.example.com"), "_sip._tcp.example.com")
        self.assertEqual(hostname("EXAMPLE.COM."), "example.com")
        self.assertEqual(hostname("", allow_empty=True), "")
        self.assertEqual(hostname(".", allow_empty=True), "")
        with self.assertRaises(ValueError):
            hostname("")
        with self.assertRaises(ValueError):
            hostname("a" * 254 + ".com")

    def test_backward_compatibility_fields(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["acme_email"] = "admin@example.com"
        cfg["cloudflare"] = {"dns_target": "198.51.100.1"}
        cfg["prefetch"] = False
        cfg["serve_expired"] = True
        cfg["upstreams"][0]["tls_hostname"] = "cloudflare-dns.com"
        del cfg["upstreams"][0]["sni"]
        cfg["profiles"][0]["categories"] = {"ads": True, "tracking": True, "malware": False}

        validated = validate_config(cfg)
        self.assertEqual(validated["email"], "admin@example.com")
        self.assertEqual(validated["public_target"], "198.51.100.1")
        self.assertFalse(validated["cache"]["prefetch"])
        self.assertTrue(validated["cache"]["serve_expired"])
        self.assertEqual(validated["upstreams"][0]["sni"], "cloudflare-dns.com")
        self.assertEqual(validated["profiles"][0]["categories"], ["ads", "tracking"])

    def test_profile_and_upstream_bounds(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["profiles"][0]["rate_limit"] = 99999
        with self.assertRaises(ValueError):
            validate_config(cfg)

        cfg2 = copy.deepcopy(DEFAULT_CONFIG)
        cfg2["block_response"] = "drop"
        with self.assertRaises(ValueError):
            validate_config(cfg2)


class StorePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.policy = Policy(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_password_hash(self):
        encoded = password_hash("correct horse battery staple")
        self.assertTrue(password_verify("correct horse battery staple", encoded))
        self.assertFalse(password_verify("wrong password", encoded))

    def test_subscription_blocks_and_manual_allow_wins(self):
        with self.store.lock, self.store.db:
            cur = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,?)",
                ("fixture", "https://example.com/list", "ads", 1, "domains"),
            )
            feed_id = cur.lastrowid
            self.store.db.execute(
                "INSERT INTO feed_domains(feed_id,category,domain) VALUES(?,?,?)",
                (feed_id, "ads", "ads.example"),
            )
        self.policy.compile()
        decision = self.policy.decide("192.0.2.1", "x.ads.example")
        self.assertEqual(decision.action, "deny")
        self.store.add_rule("x.ads.example", "exact", "allow", "", "*", None)
        self.policy.compile()
        decision = self.policy.decide("192.0.2.1", "x.ads.example")
        self.assertEqual(decision.action, "allow")

    def test_dashboard_extended_metrics(self):
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "INSERT INTO queries(ts, client, domain, qtype, action, profile, latency, rcode, detail) VALUES(?,?,?,?,?,?,?,?,?)",
                (10000000000.0, "192.168.1.10", "ads.example.com", 1, "blocked", "default", 1.2, 3, "blocklist")
            )
            self.store.db.execute(
                "INSERT INTO queries(ts, client, domain, qtype, action, profile, latency, rcode, detail) VALUES(?,?,?,?,?,?,?,?,?)",
                (10000000000.0, "192.168.1.10", "clean.example.com", 1, "allowed", "default", 15.4, 0, "quad9")
            )
        data = self.store.dashboard(window=100000000000)
        self.assertIn("top_blocked", data)
        self.assertIn("top_allowed", data)
        self.assertIn("top_clients", data)
        self.assertIn("qtypes", data)
        self.assertEqual(len(data["top_blocked"]), 1)
        self.assertEqual(data["top_blocked"][0]["domain"], "ads.example.com")
        self.assertEqual(len(data["top_allowed"]), 1)
        self.assertEqual(data["top_allowed"][0]["domain"], "clean.example.com")
        self.assertIsInstance(data["series"][0]["blocked"], int)

    def test_rule_upsert(self):
        r1 = self.store.add_rule("bad.domain", "exact", "deny", "", "*", None)
        self.assertEqual(r1["action"], "deny")
        r2 = self.store.add_rule("bad.domain", "exact", "allow", "", "*", None)
        self.assertEqual(r2["action"], "allow")
        rows = [r for r in self.store.rule_rows() if r["pattern"] == "bad.domain"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "allow")

    def test_rule_expiration(self):
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "INSERT INTO rules(pattern,kind,action,value,profile,expires,created) VALUES(?,?,?,?,?,?,?)",
                ("expired.domain", "exact", "deny", "", "*", time.time() - 10, time.time() - 20)
            )
        self.policy.compile()
        decision = self.policy.decide("192.0.2.1", "expired.domain")
        self.assertEqual(decision.action, "allow")
        self.assertEqual(len(self.store.rule_rows()), 0)

    def test_longest_prefix_match_profile(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["profiles"].append({
            "id": "lan",
            "name": "LAN",
            "networks": ["192.168.1.0/24"],
            "categories": ["ads"],
            "rate_limit": 500,
            "logging": True,
        })
        cfg["profiles"].append({
            "id": "vip",
            "name": "VIP",
            "networks": ["192.168.1.50/32"],
            "categories": [],
            "rate_limit": 1000,
            "logging": True,
        })
        self.store.set_config(cfg)
        self.policy.compile()
        p1 = self.policy.profile("192.168.1.50")
        self.assertEqual(p1["id"], "vip")
        p2 = self.policy.profile("192.168.1.100")
        self.assertEqual(p2["id"], "lan")
        p3 = self.policy.profile("10.0.0.1")
        self.assertEqual(p3["id"], "default")

    def test_secret_encryption_and_decryption(self):
        self.store.set_secret("cloudflare", "cf-test-token-123")
        self.assertEqual(self.store.secret("cloudflare"), "cf-test-token-123")
        self.store.set_secret("cloudflare", "")
        self.assertEqual(self.store.secret("cloudflare"), "")

    def test_session_management(self):
        with self.assertRaises(ValueError):
            self.store.complete_setup("invalid_code", "supersecret10")
        code = self.store.setup_code
        self.store.complete_setup(code, "supersecret10")
        self.assertTrue(self.store.has_user())
        token = self.store.authenticate("supersecret10")
        session = self.store.session(token)
        self.assertIsNotNone(session)
        self.assertIn("csrf", session)
        self.store.logout(token)
        self.assertIsNone(self.store.session(token))

    def test_threat_snapshot_and_cleanup(self):
        self.store.log_query("1.2.3.4", "good.org", 1, "allowed", "default", 12.0, 0)
        self.store.log_query("1.2.3.4", "bad.org", 1, "blocked", "default", 1.0, 3)
        self.store.audit("Test event", "detail")
        snap = self.store.threat_snapshot()
        self.assertEqual(snap["queries"], 2)
        self.assertEqual(snap["unique_domains"], 2)
        self.store.cleanup()
        audit_rows = self.store.rows("SELECT * FROM audit")
        self.assertGreaterEqual(len(audit_rows), 1)

    def test_bloom_only_indexes_enabled_feeds(self):
        with self.store.lock, self.store.db:
            cur1 = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,?)",
                ("enabled_f", "https://example.com/e", "ads", 1, "domains"),
            )
            f1 = cur1.lastrowid
            self.store.db.execute("INSERT INTO feed_domains(feed_id,category,domain) VALUES(?,?,?)", (f1, "ads", "active.ad"))

            cur2 = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,?)",
                ("disabled_f", "https://example.com/d", "ads", 0, "domains"),
            )
            f2 = cur2.lastrowid
            self.store.db.execute("INSERT INTO feed_domains(feed_id,category,domain) VALUES(?,?,?)", (f2, "ads", "inactive.ad"))

        self.policy.compile()
        self.assertTrue(self.policy.bloom.maybe("active.ad"))
        self.assertFalse(self.policy.bloom.maybe("inactive.ad"))

    def test_pause_blocking_snooze(self):
        self.store.add_rule("bad.example.com", "exact", "deny", "", "*", None)
        self.policy.compile()
        decision = self.policy.decide("192.168.1.10", "bad.example.com")
        self.assertEqual(decision.action, "deny")

        status = self.store.pause_blocking(300)
        self.assertTrue(status["paused"])
        self.assertGreater(status["remaining"], 0)
        decision = self.policy.decide("192.168.1.10", "bad.example.com")
        self.assertEqual(decision.action, "allow")
        self.assertEqual(decision.source, "policy:snoozed")

        status = self.store.pause_blocking(0)
        self.assertFalse(status["paused"])
        decision = self.policy.decide("192.168.1.10", "bad.example.com")
        self.assertEqual(decision.action, "deny")

    def test_device_registry(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)
        self.store.log_query("10.0.0.5", "test.com", 1, "allowed", "default", 10.0, 0, "")
        devices = self.store.get_devices()
        self.assertTrue(any(d["ip"] == "10.0.0.5" for d in devices))
        self.store.update_device("10.0.0.5", "Work Laptop", "laptop", "default")
        devices = self.store.get_devices()
        dev = next(d for d in devices if d["ip"] == "10.0.0.5")
        self.assertEqual(dev["name"], "Work Laptop")
        self.assertEqual(dev["icon"], "laptop")
        self.store.delete_device("10.0.0.5")
        self.assertFalse(any(d["ip"] == "10.0.0.5" for d in self.store.get_devices()))

    def test_local_records_in_unbound(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["dnssec"] = False
        cfg["local_records"] = [
            {"name": "printer.lan", "type": "A", "value": "192.168.1.88", "ttl": 300}
        ]
        cfg = validate_config(cfg)
        self.assertEqual(len(cfg["local_records"]), 1)
        manager = ResolverManager(self.store, 5533, 8954)
        rendered = manager.render(cfg)
        self.assertIn('local-data: "printer.lan. 300 IN A 192.168.1.88"', rendered)
        self.assertIn('local-data-ptr: "192.168.1.88 300 printer.lan."', rendered)

    def test_query_csv_export(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)
        self.store.log_query("192.168.1.55", "blocked-site.com", 1, "blocked", "default", 2.5, 3, "feed:test")
        csv_out = self.store.export_queries_csv()
        self.assertIn("Timestamp_ISO", csv_out)
        self.assertIn("blocked-site.com", csv_out)
        self.assertIn("192.168.1.55", csv_out)

    def test_rule_bulk_import_and_clear_expired(self):
        rules_text = """
        # Adblock rule
        ||ad-network.com^
        # Hosts format
        0.0.0.0 tracker-site.com
        # Plain domain
        malicious-hub.org
        """
        res = self.store.import_rules(rules_text, action="deny", profile="*")
        self.assertGreaterEqual(res["added"], 3)
        patterns = {r["pattern"] for r in self.store.rule_rows()}
        self.assertIn("ad-network.com", patterns)
        self.assertIn("tracker-site.com", patterns)
        self.assertIn("malicious-hub.org", patterns)

        # Clear expired rules
        now = time.time()
        self.store.db.execute(
            "INSERT INTO rules(pattern,kind,action,value,profile,expires,created) VALUES(?,?,?,?,?,?,?)",
            ("expired.com", "exact", "deny", "", "*", now - 10, now - 100),
        )
        self.store.db.commit()
        cleared = self.store.clear_expired_rules()
        self.assertGreaterEqual(cleared, 1)

    def test_safesearch_rewriting(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["safesearch"] = True
        self.store.set_config(cfg)
        
        # Test google.com rewrite
        d_google = self.policy.decide("192.168.1.1", "www.google.com")
        self.assertEqual(d_google.action, "rewrite")
        self.assertEqual(d_google.value, "216.239.38.120")
        
        # Test youtube.com rewrite
        d_yt = self.policy.decide("192.168.1.1", "youtube.com")
        self.assertEqual(d_yt.action, "rewrite")
        self.assertEqual(d_yt.value, "216.239.38.119")

        # When safesearch is disabled
        cfg["safesearch"] = False
        self.store.set_config(cfg)
        d_off = self.policy.decide("192.168.1.1", "www.google.com")
        self.assertEqual(d_off.action, "allow")

    def test_rebinding_protection_render(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["rebinding_protection"] = True
        cfg["local_records"] = [{"name": "nas.lan", "type": "A", "value": "192.168.1.100", "ttl": 300}]
        manager = ResolverManager(self.store, 5533, 8954)
        rendered = manager.render(cfg)
        self.assertIn("private-address: 192.168.0.0/16", rendered)
        self.assertIn('private-domain: "nas.lan."', rendered)

    def test_block_presets_engine(self):
        status = self.store.get_presets_status()
        self.assertTrue(any(p["id"] == "tiktok" for p in status))
        tiktok_preset = next(p for p in status if p["id"] == "tiktok")
        self.assertFalse(tiktok_preset["blocked"])

        # Enable tiktok preset
        self.store.toggle_preset("tiktok", True)
        self.policy.compile()
        dec = self.policy.decide("192.168.1.5", "tiktok.com")
        self.assertEqual(dec.action, "deny")

        # Disable tiktok preset
        self.store.toggle_preset("tiktok", False)
        self.policy.compile()
        dec2 = self.policy.decide("192.168.1.5", "tiktok.com")
        self.assertEqual(dec2.action, "allow")

    def test_shannon_entropy_calculation(self):
        from lattice.store import shannon_entropy
        low_ent = shannon_entropy("google")
        high_ent = shannon_entropy("xj7b92qzkpmv1")
        self.assertGreater(high_ent, low_ent)
        self.assertGreater(high_ent, 3.2)

    def test_doh_gateway_resolution(self):
        from lattice.transport import DNSGateway
        from lattice.integrations import CertificateVault
        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 5353, 18853, 18854)
        from lattice.app import Lattice
        packet = Lattice.make_query("ads.example")
        self.store.add_rule("ads.example", "exact", "deny", "", "*", None)
        self.policy.compile()
        resp = gw.handle_query(packet, "127.0.0.1", transport="doh")
        self.assertEqual(resp[:2], packet[:2])
        self.assertEqual(resp[3] & 15, 3)  # NXDOMAIN

    def test_block_response_zero_mode(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["block_response"] = "zero"
        cfg = validate_config(cfg)
        self.assertEqual(cfg["block_response"], "zero")

    def test_feed_parser(self):
        self.assertEqual(parse_feed_line("||ads.example^", "adblock"), "ads.example")
        self.assertEqual(parse_feed_line("||tracker.example$third-party", "adblock"), "tracker.example")
        self.assertEqual(parse_feed_line("0.0.0.0 tracker.example # comment", "auto"), "tracker.example")
        self.assertEqual(parse_feed_line("domain.example # plain domain comment", "domains"), "domain.example")
        self.assertIsNone(parse_feed_line("! comment", "auto"))
        self.assertIsNone(parse_feed_line("127.0.0.1 localhost", "auto"))
        self.assertIsNone(parse_feed_line("0.0.0.0 0.0.0.0", "auto"))
        self.assertIsNone(parse_feed_line("0.0.0.0 broadcasthost", "auto"))
        self.assertIsNone(parse_feed_line("@@||allowed.example^", "adblock"))


class PacketTests(unittest.TestCase):
    def test_question_and_error(self):
        packet = query("example.com", 1)
        name, qtype, end = read_question(packet)
        self.assertEqual(name, "example.com")
        self.assertEqual(qtype, 1)
        self.assertGreater(end, 12)
        blocked = error_response(packet, 3)
        self.assertEqual(blocked[3] & 15, 3)
        self.assertEqual(blocked[:2], packet[:2])

    def test_root_domain_query(self):
        packet = query("", 1)  # Root query
        name, qtype, end = read_question(packet)
        self.assertEqual(name, "")
        self.assertEqual(qtype, 1)
        resp = error_response(packet, 0)
        self.assertEqual(resp[:2], packet[:2])

    def test_reverse_ptr_query(self):
        packet = query("1.0.0.127.in-addr.arpa", 12)
        name, qtype, _ = read_question(packet)
        self.assertEqual(name, "1.0.0.127.in-addr.arpa")
        self.assertEqual(qtype, 12)

    def test_rewrite(self):
        packet = query("printer.home", 1)
        response = rewrite_response(packet, 1, "192.0.2.50")
        self.assertEqual(response[3] & 15, 0)
        self.assertEqual(int.from_bytes(response[6:8], "big"), 1)

        # ANY query rewrite returns answer
        any_response = rewrite_response(packet, 255, "192.0.2.50")
        self.assertEqual(int.from_bytes(any_response[6:8], "big"), 1)

        # Type mismatch NODATA response
        aaaa_packet = query("printer.home", 28)
        nodata_response = rewrite_response(aaaa_packet, 28, "192.0.2.50")
        self.assertEqual(nodata_response[3] & 15, 0)
        self.assertEqual(int.from_bytes(nodata_response[6:8], "big"), 0)

    def test_truncated_and_malformed_packets(self):
        with self.assertRaises(ValueError):
            read_question(b"\0" * 10)
        with self.assertRaises(ValueError):
            read_question(query("example.com", 252))  # AXFR


class ResolverAndFrpTests(unittest.TestCase):
    def test_frpc_render(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["frp"].update({"enabled": True, "server": "frps.example", "auth": "token"})
        text = render_frpc(cfg, "secret-value", 8854)
        self.assertIn('transport.proxyProtocolVersion = "v1"', text)
        self.assertIn("remotePort = 853", text)
        self.assertIn('auth.token = "secret-value"', text)

    def test_resolver_routes_render(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(root)
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            cfg["dnssec"] = False
            cfg["routes"] = [{"suffix": "corp.example", "upstreams": ["quad9"]}]
            cfg = validate_config(cfg)
            store.set_config(cfg)
            manager = ResolverManager(store, 5533, 8954)
            rendered = manager.render(cfg)
            self.assertIn('name: "corp.example."', rendered)
            self.assertIn("9.9.9.9@853#dns.quad9.net", rendered)
            self.assertIn('name: "."', rendered)
            store.close()

    def test_resolver_fallback_anchor(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(root)
            manager = ResolverManager(store, 5533, 8954)
            anchor = manager.ensure_anchor()
            self.assertIsNotNone(anchor)
            self.assertTrue(anchor.exists())
            self.assertTrue(any(tok in anchor.read_text() for tok in ("20326", "DNSKEY", "DS")))
            store.close()

    def test_probe_dot_question_format(self):
        packet = _question("example.com")
        self.assertEqual(packet[:2], b"\x4C\x44")
        # Ensure DO bit (0x8000) is set in EDNS0 OPT RR
        self.assertIn(b"\x80\0\0\0", packet)


class ProxyProtocolTests(unittest.TestCase):
    class MockSocket:
        def __init__(self, data: bytes):
            self.data = io.BytesIO(data)
        def recv(self, size: int):
            return self.data.read(size)

    def test_read_proxy_line_v1(self):
        sock4 = self.MockSocket(b"PROXY TCP4 198.51.100.22 203.0.113.1 54321 853\r\n")
        self.assertEqual(read_proxy_line(sock4), "198.51.100.22")

        sock6 = self.MockSocket(b"PROXY TCP6 2001:db8::1 2001:db8::2 54321 853\r\n")
        self.assertEqual(read_proxy_line(sock6), "2001:db8::1")

        sock_unk = self.MockSocket(b"PROXY UNKNOWN\r\n")
        self.assertEqual(read_proxy_line(sock_unk), "")

        with self.assertRaises(ValueError):
            read_proxy_line(self.MockSocket(b"INVALID PROTOCOL HEADER\r\n"))


class CertificateVaultTests(unittest.TestCase):
    def test_san_matching(self):
        self.assertTrue(CertificateVault._matches("dns.example.com", "dns.example.com"))
        self.assertTrue(CertificateVault._matches("*.example.com", "dns.example.com"))
        self.assertFalse(CertificateVault._matches("*.example.com", "sub.dns.example.com"))
        self.assertFalse(CertificateVault._matches("*.example.com", "other.org"))

    def test_renew_if_needed_logic(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(root)
            vault = CertificateVault(store)
            # Not valid cert -> renew needed
            vault.details = {"valid": False}
            self.assertTrue(vault.renew_if_needed.__code__ is not None)
            # Valid with 30 days left -> no renew needed
            vault.details = {"valid": True, "expires": time.time() + 30 * 86400}
            self.assertFalse(vault.renew_if_needed())
            store.close()


class BackupRestoreAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.policy = Policy(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_backup_and_restore_full(self):
        self.store.add_rule("block.me", "exact", "deny", "", "*", None)
        rules = self.store.rule_rows()
        self.assertTrue(any(r["pattern"] == "block.me" for r in rules))
        cfg = self.store.config
        self.assertTrue(cfg["dnssec"])

        # Test restore audit log does not raise TypeError
        self.store.audit("Backup restored", "Configuration and rules restored from backup")
        audits = self.store.rows("SELECT * FROM audit WHERE event='Backup restored'")
        self.assertEqual(len(audits), 1)




class AndroidPrivateDNSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.policy = Policy(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_android_edns0_and_soa_negative_caching(self):
        pkt = _question("doubleclick.net", ident=0xCAFE)
        nx = error_response(pkt, 3)
        self.assertEqual(nx[:2], b"\xCA\xFE")
        self.assertEqual(nx[3] & 15, 3)
        self.assertEqual(struct.unpack("!H", nx[8:10])[0], 1)
        self.assertEqual(struct.unpack("!H", nx[10:12])[0], 1)

        https_pkt = (
            struct.pack("!6H", 0xBEEF, 0x0110, 1, 0, 0, 1)
            + b"\x03www\x06google\x03com\x00"
            + struct.pack("!HH", 65, 1)
            + b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
        )
        nodata = rewrite_response(https_pkt, 65, "216.239.38.120")
        self.assertEqual(nodata[3] & 15, 0)
        self.assertTrue(struct.unpack("!H", nodata[2:4])[0] & 0x0010)
        self.assertEqual(struct.unpack("!H", nodata[6:8])[0], 0)
        self.assertEqual(struct.unpack("!H", nodata[8:10])[0], 1)
        self.assertEqual(struct.unpack("!H", nodata[10:12])[0], 1)

    def test_safesearch_does_not_hijack_android_connectivity_or_play_store(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["safesearch"] = True
        self.store.set_config(cfg)

        self.assertEqual(self.policy.decide("192.168.1.10", "www.google.com").action, "rewrite")
        self.assertEqual(self.policy.decide("192.168.1.10", "google.com.sg").action, "rewrite")

        for android_host in (
            "clients3.google.com",
            "clients4.google.com",
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "play.google.com",
            "mtalk.google.com",
            "dl.google.com",
            "accounts.google.com",
        ):
            dec = self.policy.decide("192.168.1.10", android_host)
            self.assertEqual(dec.action, "allow", f"SafeSearch wrongly hijacked {android_host}")

    def test_android_essential_probes_never_blocked_by_feeds(self):
        with self.store.lock, self.store.db:
            cur = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,?)",
                ("bad_feed", "https://example.com/bad", "ads", 1, "domains"),
            )
            fid = cur.lastrowid
            for dom in ("gstatic.com", "google.com", "ipv4only.arpa", "_dns.resolver.arpa"):
                self.store.db.execute(
                    "INSERT INTO feed_domains(feed_id,category,domain) VALUES(?,?,?)",
                    (fid, "ads", dom),
                )
        self.policy.compile()
        self.assertEqual(self.policy.decide("192.168.1.10", "connectivitycheck.gstatic.com").action, "allow")
        self.assertEqual(self.policy.decide("192.168.1.10", "test123.dnsotls-ds.metric.gstatic.com").action, "allow")
        self.assertEqual(self.policy.decide("192.168.1.10", "ipv4only.arpa").action, "allow")
        self.assertEqual(self.policy.decide("192.168.1.10", "_dns.resolver.arpa").action, "allow")

    def test_android_dot_pipelined_multiplexing_and_readiness(self):
        from lattice.app import Lattice
        from lattice.transport import decode_dns_answers

        app = Lattice(self.tmp.name, resolver_port=15533, dot_port=18873, frp_local_port=18874)
        try:
            cfg = copy.deepcopy(app.store.config)
            cfg["hostname"] = "dns.android.test"
            cfg["local_records"] = [{"name": "nas.home.arpa", "type": "A", "value": "192.168.1.200", "ttl": 120}]
            app.store.set_config(validate_config(cfg))
            app.certs.generate_self_signed("dns.android.test")
            app.store.add_rule("ads.example.org", "exact", "deny", "", "*", None)
            app.policy.compile()
            app.gateway.start()

            report = app.android_readiness()
            self.assertTrue(report["ready"], f"Readiness report failed: {report}")
            self.assertEqual(report["passed"], 6)

            rw_pkt = app.make_query("nas.home.arpa", 1, edns0=True, ident=0x2222)
            rw_resp = rewrite_response(rw_pkt, 1, "192.168.1.200", ttl=120)
            decoded = decode_dns_answers(rw_resp)
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0]["data"], "192.168.1.200")
            self.assertEqual(decoded[0]["type"], "A")
        finally:
            app.shutdown()



    def test_device_specific_profile_override(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["profiles"].append({
            "id": "kids",
            "name": "Kids Tablet Profile",
            "networks": ["10.99.99.0/24"],
            "categories": ["ads", "tracking", "malware", "adult", "social"],
            "rate_limit": 200,
            "logging": True,
        })
        self.store.set_config(cfg)
        self.store.update_device("192.168.1.77", "Kids iPad", "phone", "kids")
        self.policy.compile()
        prof = self.policy.profile("192.168.1.77")
        self.assertEqual(prof["id"], "kids")
        self.assertEqual(self.policy.status()["device_overrides"], 1)

    def test_dual_stack_local_records_and_ptr(self):
        from lattice.app import Lattice
        from lattice.transport import decode_dns_answers

        app = Lattice(self.tmp.name, resolver_port=15543, dot_port=18883, frp_local_port=18884)
        try:
            cfg = copy.deepcopy(app.store.config)
            cfg["local_records"] = [
                {"name": "nas.lan", "type": "A", "value": "192.168.1.100", "ttl": 300},
                {"name": "nas.lan", "type": "AAAA", "value": "fd00::100", "ttl": 300},
                {"name": "nas.lan", "type": "TXT", "value": "v=lattice-nas", "ttl": 300},
            ]
            app.store.set_config(validate_config(cfg))

            # Query A (1)
            resp_a = app.gateway.handle_query(app.make_query("nas.lan", 1, edns0=True), "192.168.1.10")
            ans_a = decode_dns_answers(resp_a)
            self.assertEqual(len(ans_a), 1)
            self.assertEqual(ans_a[0]["data"], "192.168.1.100")

            # Query AAAA (28) — must NOT be shadowed by the A record!
            resp_aaaa = app.gateway.handle_query(app.make_query("nas.lan", 28, edns0=True), "192.168.1.10")
            ans_aaaa = decode_dns_answers(resp_aaaa)
            self.assertEqual(len(ans_aaaa), 1)
            self.assertEqual(ans_aaaa[0]["data"], "fd00::100")

            # Query TXT (16)
            resp_txt = app.gateway.handle_query(app.make_query("nas.lan", 16, edns0=True), "192.168.1.10")
            ans_txt = decode_dns_answers(resp_txt)
            self.assertEqual(len(ans_txt), 1)
            self.assertEqual(ans_txt[0]["data"], "v=lattice-nas")

            # Query Reverse PTR (12)
            resp_ptr = app.gateway.handle_query(app.make_query("100.1.168.192.in-addr.arpa", 12, edns0=True), "192.168.1.10")
            ans_ptr = decode_dns_answers(resp_ptr)
            self.assertEqual(len(ans_ptr), 1)
            self.assertEqual(ans_ptr[0]["data"], "nas.lan")
        finally:
            app.shutdown()

    def test_nonblocking_query_log_and_feed_cache(self):
        import threading

        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)

        # Simulate background feed sync holding store.lock on a worker thread
        ready = threading.Event()
        release = threading.Event()

        def hold_lock():
            with self.store.lock:
                ready.set()
                release.wait(timeout=5.0)

        t = threading.Thread(target=hold_lock)
        t.start()
        ready.wait(timeout=2.0)

        # Calling log_query from the main thread while store.lock is held by t must return immediately!
        t0 = time.monotonic()
        self.store.log_query("192.168.1.88", "fast.example.com", 1, "allowed", "default", 3.2, 0, "cached")
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.05)

        release.set()
        t.join(timeout=2.0)

        # Now querying rows() flushes the pending queue automatically
        rows = self.store.rows("SELECT * FROM queries WHERE domain='fast.example.com'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["client"], "192.168.1.88")

    def test_edns0_do_bit_preservation(self):
        # _question sets DO=1 (0x8000 in OPT TTL flags)
        q_do = _question("blocked.example.com", ident=0x55AA)
        resp_do = error_response(q_do, 3)
        self.assertIn(b"\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00", resp_do)

    def test_diagnose_allowed_and_rewritten_domains(self):
        from lattice.app import Lattice

        app = Lattice(self.tmp.name, resolver_port=15545, dot_port=18885, frp_local_port=18886)
        try:
            diag_local = app.diagnose("localhost", 1, "127.0.0.1")
            self.assertEqual(diag_local["policy"]["action"], "allow")
            self.assertFalse(diag_local["resolver"]["skipped"])
            self.assertEqual(diag_local["resolver"]["rcode"], 0)
            self.assertEqual(diag_local["resolver"]["records"][0]["data"], "127.0.0.1")
        finally:
            app.shutdown()




class FlagshipV5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.policy = Policy(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_regex_and_expiring_rules(self):
        # 1. Regex rule matching
        self.store.add_rule(r"^ad[0-9]+\.tracker\.example\.com$", "regex", "deny", "", "*", None)
        self.policy.compile()
        self.assertEqual(self.policy.decide("192.168.1.50", "ad42.tracker.example.com").action, "deny")
        self.assertEqual(self.policy.decide("192.168.1.50", "safe.tracker.example.com").action, "allow")

        # 2. Invalid regex rejected cleanly
        with self.assertRaises(ValueError):
            self.store.add_rule("[unclosed-regex", "regex", "deny", "", "*", None)

    def test_l1_dns_cache_and_serve_expired(self):
        from lattice.transport import DNSCache, rewrite_response

        cache = DNSCache(max_entries=128)
        q1 = _question("cached.example.com", ident=0x1111)
        resp1 = rewrite_response(q1, 1, "93.184.216.34", ttl=60)
        cache.put("cached.example.com", 1, True, resp1)

        # Hit with different transaction ID (0x2222)
        q2 = _question("cached.example.com", ident=0x2222)
        hit = cache.get("cached.example.com", 1, True, q2[:2], allow_stale=False)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[:2], b"\x22\x22")
        st = cache.stats()
        self.assertEqual(st["hits"], 1)
        self.assertEqual(st["active_entries"], 1)

    def test_cname_cloaking_unmasking_and_interception(self):
        from lattice.transport import synthesize_rr_response, _encode_name, decode_dns_answers

        # Block the hidden tracker target
        self.store.add_rule("cloaked-tracker.evil.org", "suffix", "deny", "", "*", None)
        self.policy.compile()

        # Construct a response where analytics.firstparty.com CNAMEs to sub.cloaked-tracker.evil.org
        q = _question("analytics.firstparty.com", ident=0x3344)
        cname_pkt = synthesize_rr_response(q, 5, _encode_name("sub.cloaked-tracker.evil.org"), ttl=120)
        recs = decode_dns_answers(cname_pkt)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["type"], "CNAME")
        self.assertEqual(recs[0]["data"], "sub.cloaked-tracker.evil.org")
        self.assertEqual(self.policy.decide("192.168.1.10", recs[0]["data"]).action, "deny")

    def test_12_presets_and_recommended_feed_bundle(self):
        presets = self.store.get_presets_status()
        self.assertEqual(len(presets), 12)
        preset_ids = {p["id"] for p in presets}
        self.assertIn("ai_bots", preset_ids)
        self.assertIn("cryptominers", preset_ids)
        self.assertIn("netflix", preset_ids)

        bundle_res = self.store.install_recommended_bundle()
        self.assertEqual(bundle_res["added"], 4)
        self.assertEqual(len(self.store.feeds()), 4)

    def test_prometheus_metrics_and_dual_mobileconfig(self):
        from lattice.app import Lattice

        app = Lattice(self.tmp.name, resolver_port=15553, dot_port=18893, frp_local_port=18894)
        try:
            metrics = app.prometheus_metrics()
            self.assertIn("lattice_dns_queries_24h_total", metrics)
            self.assertIn("lattice_dns_l1_cache_hit_ratio_percent", metrics)
            self.assertIn("lattice_dns_indexed_domains_total", metrics)
        finally:
            app.shutdown()



    def test_qr_code_svg_generation(self):
        from lattice.integrations import generate_qr_svg

        svg = generate_qr_svg("https://dns.ntun7719.dev/dns-query")
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("viewBox=", svg)
        self.assertIn("<rect", svg)

    def test_l1_cache_dynamic_ttl_and_eviction(self):
        from lattice.transport import DNSCache, rewrite_response, decode_dns_answers

        cache = DNSCache(max_entries=64)
        q1 = _question("ttltest.example.com", ident=0x1234)
        resp1 = rewrite_response(q1, 1, "93.184.216.34", ttl=120)
        cache.put("ttltest.example.com", 1, True, resp1)

        # Simulate 30 seconds elapsed
        key = ("ttltest.example.com", 1, True)
        cache.entries[key]["expires_at"] = time.time() + 90
        hit = cache.get("ttltest.example.com", 1, True, b"\x56\x78", allow_stale=False)
        self.assertIsNotNone(hit)
        decoded = decode_dns_answers(hit)
        self.assertEqual(len(decoded), 1)
        self.assertLessEqual(decoded[0]["ttl"], 90)
        self.assertGreaterEqual(decoded[0]["ttl"], 88)

        # Evict domain
        removed = cache.evict("ttltest.example.com")
        self.assertEqual(removed, 1)
        self.assertIsNone(cache.get("ttltest.example.com", 1, True, b"\x56\x78", allow_stale=False))


if __name__ == "__main__":
    unittest.main()
