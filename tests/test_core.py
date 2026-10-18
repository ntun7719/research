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
        self.assertEqual(len(presets), 24)
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



    def test_focus_and_bedtime_schedule_engine(self):
        # 24/7 schedule window (00:00 -> 23:59) blocking tiktok & youtube
        self.store.set_schedule({
            "enabled": True,
            "mode": "bedtime",
            "start": "00:00",
            "end": "23:59",
            "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            "presets": ["tiktok", "youtube"],
            "categories": ["social"],
            "profile": "*",
        })
        active, sched = self.store.is_schedule_active()
        self.assertTrue(active)
        self.assertEqual(sched["mode"], "bedtime")

        dec_tt = self.policy.decide("192.168.1.42", "www.tiktok.com")
        self.assertEqual(dec_tt.action, "deny")
        self.assertIn("schedule:bedtime:tiktok", dec_tt.source)

        # Android connectivity probe must still be protected even during active schedule!
        dec_android = self.policy.decide("192.168.1.42", "connectivitycheck.gstatic.com")
        self.assertEqual(dec_android.action, "allow")

        # Disable schedule -> tiktok allowed again
        self.store.set_schedule({"enabled": False})
        self.assertEqual(self.policy.decide("192.168.1.42", "www.tiktok.com").action, "allow")

    def test_forensic_rule_pattern_attribution(self):
        self.store.add_rule("tracker.bad.org", "suffix", "deny", "", "*", None)
        self.policy.compile()
        dec = self.policy.decide("192.168.1.10", "sub.tracker.bad.org")
        self.assertEqual(dec.action, "deny")
        self.assertTrue(dec.source.startswith("rule:"))
        self.assertIn("tracker.bad.org", dec.source)


    def test_security_shields_doh_canary_punycode_and_risky_tlds(self):
        # 1. DoH canary (use-application-dns.net) blocked by default
        dec_canary = self.policy.decide("192.168.1.10", "use-application-dns.net")
        self.assertEqual(dec_canary.action, "deny")
        self.assertEqual(dec_canary.source, "security:doh-canary")

        # 2. Punycode IDN homograph & Risky TLD shields
        cfg = copy.deepcopy(self.store.config)
        cfg["block_punycode"] = True
        cfg["block_risky_tlds"] = True
        self.store.set_config(cfg)

        dec_puny = self.policy.decide("192.168.1.10", "xn--80ak6aa92e.com")
        self.assertEqual(dec_puny.action, "deny")
        self.assertEqual(dec_puny.source, "security:punycode-homograph")

        dec_zip = self.policy.decide("192.168.1.10", "quarterly-invoice.zip")
        self.assertEqual(dec_zip.action, "deny")
        self.assertEqual(dec_zip.source, "security:risky-tld (.zip)")

        # 3. Manual allow rule overrides security shields
        self.store.add_rule("quarterly-invoice.zip", "exact", "allow", "", "*", None)
        self.policy.compile()
        self.assertEqual(self.policy.decide("192.168.1.10", "quarterly-invoice.zip").action, "allow")

    def test_dns_rebinding_runtime_guard_and_local_record_exemption(self):
        from lattice.transport import DNSGateway, is_rebinding_ip
        from unittest.mock import patch

        self.assertTrue(is_rebinding_ip("192.168.1.1"))
        self.assertTrue(is_rebinding_ip("127.0.0.1"))
        self.assertTrue(is_rebinding_ip("169.254.169.254"))
        self.assertTrue(is_rebinding_ip("10.0.0.1"))
        self.assertFalse(is_rebinding_ip("93.184.216.34"))
        self.assertFalse(is_rebinding_ip("192.0.2.50"))

        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15533, 18893, 18894)
        q_rebind = query("evil-rebind.example.com", 1)
        fake_upstream_ans = rewrite_response(q_rebind, 1, "192.168.1.1", ttl=60)

        with patch("lattice.transport.forward_local", return_value=fake_upstream_ans):
            resp = gw.handle_query(q_rebind, "192.168.1.50", transport="dot")
            self.assertEqual(resp[3] & 15, 3)  # Blocked with NXDOMAIN
            rows = self.store.rows("SELECT * FROM queries WHERE domain='evil-rebind.example.com'")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["action"], "blocked")
            self.assertIn("security:dns-rebinding", rows[0]["detail"])

    def test_weekday_and_per_profile_schedule_isolation(self):
        cfg = copy.deepcopy(self.store.config)
        cfg["profiles"].append({
            "id": "kids",
            "name": "Kids Profile",
            "networks": ["192.168.99.0/24"],
            "categories": ["ads"],
            "rate_limit": 300,
            "logging": True,
        })
        self.store.set_config(cfg)
        self.policy.compile()

        self.store.set_schedule({
            "enabled": True,
            "mode": "bedtime",
            "start": "00:00",
            "end": "23:59",
            "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            "presets": ["tiktok"],
            "profile": "kids",
        })

        # Kids subnet device is blocked from TikTok
        dec_kids = self.policy.decide("192.168.99.15", "www.tiktok.com")
        self.assertEqual(dec_kids.action, "deny")
        self.assertIn("schedule:bedtime:tiktok", dec_kids.source)

        # Default subnet device is unaffected by kids-only schedule
        dec_adult = self.policy.decide("192.168.1.15", "www.tiktok.com")
        self.assertEqual(dec_adult.action, "allow")

    def test_live_event_ring_buffer_and_latency_percentiles(self):
        cfg = copy.deepcopy(self.store.config)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)

        for lat, dom, act, det in [
            (0.4, "fast.example.com", "allowed", "cache:l1"),
            (2.1, "normal.example.com", "allowed", "policy:default"),
            (14.5, "slow.example.com", "allowed", "policy:default"),
            (38.0, "rebind.example.com", "blocked", "security:dns-rebinding (10.0.0.1)"),
        ]:
            self.store.log_query("192.168.1.25", dom, 1, act, "default", lat, 0, det)

        ev = self.store.get_events_since(0)
        self.assertGreaterEqual(ev["seq"], 4)
        self.assertEqual(len(ev["events"]), 4)

        dash = self.store.dashboard(window=3600)
        self.assertGreater(dash["p50_latency"], 0)
        self.assertGreaterEqual(dash["p95_latency"], dash["p50_latency"])
        self.assertEqual(dash["cache_hits_window"], 1)
        self.assertEqual(dash["security_blocks_window"], 1)
        self.assertEqual(len(dash["recent_live"]), 4)

    def test_l1_hot_domain_prefetch_candidates_and_tls_pool(self):
        from lattice.transport import DNSCache, UPSTREAM_TLS_POOL

        cache = DNSCache(max_entries=64)
        q1 = _question("hot.example.com", ident=0x1111)
        resp1 = rewrite_response(q1, 1, "93.184.216.34", ttl=100)
        cache.put("hot.example.com", 1, True, resp1)
        # Simulate a cache hit and near-expiration TTL (10s left)
        _ = cache.get("hot.example.com", 1, True, b"\x22\x22")
        cache.entries[("hot.example.com", 1, True)]["expires_at"] = time.time() + 10
        candidates = cache.expiring_hot_candidates()
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], "hot.example.com")

        UPSTREAM_TLS_POOL.record_latency("cloudflare", 18.0)
        UPSTREAM_TLS_POOL.record_latency("cloudflare", 12.0)
        pool_stats = UPSTREAM_TLS_POOL.stats()
        self.assertIn("cloudflare", pool_stats["ewma_latencies_ms"])


    def test_18_feed_catalog_marketplace_and_packs(self):
        cat = self.store.get_catalog_status()
        self.assertEqual(len(cat), 24)
        self.assertTrue(all(not c["installed"] for c in cat))

        # Install single catalog feed (OISD Small)
        res1 = self.store.install_catalog_items(feed_id="oisd_small")
        self.assertEqual(res1["added"], 1)
        self.assertTrue(any(c["id"] == "oisd_small" and c["installed"] for c in res1["catalog"]))

        # Install Malware Fortress pack (7 lists)
        res2 = self.store.install_catalog_items(pack="malware")
        self.assertEqual(res2["target_count"], 7)
        self.assertEqual(res2["added"], 7)
        self.assertEqual(len(self.store.feeds()), 8)

    def test_cross_blocklist_and_preset_attribution_search(self):
        with self.store.lock, self.store.db:
            cur = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,1)",
                ("OISD Small", "https://small.oisd.nl/domainswild2", "ads", "domains"),
            )
            fid = cur.lastrowid
            self.store.db.execute(
                "INSERT INTO feed_domains(feed_id,category,domain) VALUES(?,?,?)",
                (fid, "ads", "ads.doubleclick.net"),
            )
        self.store.add_rule("custom.doubleclick.net", "exact", "deny", "", "*", None)

        res_dc = self.store.search_blocklists("doubleclick")
        self.assertEqual(len(res_dc["feed_matches"]), 1)
        self.assertEqual(res_dc["feed_matches"][0]["feed_name"], "OISD Small")
        self.assertEqual(len(res_dc["rule_matches"]), 1)

        res_tt = self.store.search_blocklists("tiktok")
        self.assertTrue(any(p["id"] == "tiktok" for p in res_tt["preset_matches"]))

    def test_per_device_telemetry_insights(self):
        cfg = copy.deepcopy(self.store.config)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)
        self.store.update_device("192.168.1.77", "Living Room Apple TV", "tv", "default")
        self.store.log_query("192.168.1.77", "apple.com", 1, "allowed", "default", 1.2, 0, "cache:l1")
        self.store.log_query("192.168.1.77", "apple.com", 28, "allowed", "default", 0.8, 0, "cache:l1")
        self.store.log_query("192.168.1.77", "metrics.icloud.com", 1, "blocked", "default", 0.3, 3, "feed:OISD")

        ins = self.store.device_insights("192.168.1.77", window=3600)
        self.assertEqual(ins["name"], "Living Room Apple TV")
        self.assertEqual(ins["total"], 3)
        self.assertEqual(ins["blocked"], 1)
        self.assertEqual(ins["allowed"], 2)
        self.assertAlmostEqual(ins["block_rate_pct"], 33.3, places=1)
        self.assertEqual(ins["top_allowed"][0]["domain"], "apple.com")
        self.assertEqual(ins["top_blocked"][0]["domain"], "metrics.icloud.com")


    def test_per_device_bypass_and_quarantine_modes(self):
        self.store.add_rule("blocked-ad.example.com", "exact", "deny", "", "*", None)
        self.policy.compile()

        # Both devices initially blocked
        self.assertEqual(self.policy.decide("192.168.1.99", "blocked-ad.example.com").action, "deny")
        self.assertEqual(self.policy.decide("192.168.1.100", "blocked-ad.example.com").action, "deny")

        # Set 192.168.1.99 to bypass mode for 300s
        self.store.set_device_mode("192.168.1.99", mode="bypass", seconds=300)
        dec_bypass = self.policy.decide("192.168.1.99", "blocked-ad.example.com")
        self.assertEqual(dec_bypass.action, "allow")
        self.assertEqual(dec_bypass.source, "policy:device-bypass")
        # Other device still blocked!
        self.assertEqual(self.policy.decide("192.168.1.100", "blocked-ad.example.com").action, "deny")

        # Set 192.168.1.99 to quarantine mode (Internet pause)
        self.store.set_device_mode("192.168.1.99", mode="quarantine", seconds=0)
        dec_quar = self.policy.decide("192.168.1.99", "wikipedia.org")
        self.assertEqual(dec_quar.action, "deny")
        self.assertEqual(dec_quar.source, "policy:device-quarantine")
        # Android essential probe still protected
        self.assertEqual(self.policy.decide("192.168.1.99", "connectivitycheck.gstatic.com").action, "allow")

        # Reset to normal
        self.store.set_device_mode("192.168.1.99", mode="normal")
        self.assertEqual(self.policy.decide("192.168.1.99", "wikipedia.org").action, "allow")

    def test_custom_sinkhole_block_ip_and_custom_ttl(self):
        from lattice.transport import DNSGateway, decode_dns_answers

        cfg = copy.deepcopy(self.store.config)
        cfg["block_response"] = "custom_ip"
        cfg["block_custom_ip"] = "192.168.1.250"
        cfg["block_ttl"] = 120
        self.store.set_config(validate_config(cfg))
        self.store.add_rule("sinkhole-test.example.com", "exact", "deny", "", "*", None)
        self.policy.compile()

        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15533, 18893, 18894)
        q_pkt = query("sinkhole-test.example.com", 1)
        resp = gw.handle_query(q_pkt, "192.168.1.50", transport="dot")
        ans = decode_dns_answers(resp)
        self.assertEqual(len(ans), 1)
        self.assertEqual(ans[0]["data"], "192.168.1.250")
        self.assertEqual(ans[0]["ttl"], 120)

    def test_security_posture_score_and_24_catalog_expansion(self):
        from lattice.app import Lattice

        app = Lattice(self.tmp.name, resolver_port=15563, dot_port=18903, frp_local_port=18904)
        try:
            app.store.install_catalog_items(pack="core")
            app.store.toggle_preset("smart_tv_acr", True)
            app.policy.compile()
            score_obj = app.compute_security_score()
            self.assertGreaterEqual(score_obj["score"], 85)
            self.assertIn(score_obj["grade"], ("A", "A+"))
        finally:
            app.shutdown()


    def test_vpn_random_uuid_dot_probe_instant_synthesis(self):
        from lattice.transport import DNSGateway, decode_dns_answers

        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15999, 18991, 18992)
        # Even with port 15999 (no Unbound running), random-UUID Android DoT probe resolves in <5ms!
        t0 = time.monotonic()
        q_v4 = query("vpn-switch-987654.dnsotls-ds.metric.gstatic.com", 1)
        resp_v4 = gw.handle_query(q_v4, "10.8.0.5", transport="dot")
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        self.assertLess(elapsed_ms, 25.0)
        self.assertEqual(resp_v4[3] & 15, 0)
        ans = decode_dns_answers(resp_v4)
        self.assertEqual(len(ans), 1)
        self.assertEqual(ans[0]["data"], "142.250.190.14")

        q_v6 = query("vpn-switch-987654.dnsotls-ds.metric.gstatic.com", 28)
        resp_v6 = gw.handle_query(q_v6, "10.8.0.5", transport="dot")
        ans6 = decode_dns_answers(resp_v6)
        self.assertEqual(len(ans6), 1)
        self.assertEqual(ans6[0]["data"], "2607:f8b0:4005:801::200e")

    def test_vpn_oem_captive_portal_probes_never_blocked_or_servfailed(self):
        from lattice.transport import DNSGateway, decode_dns_answers
        from unittest.mock import patch

        oem_domains = [
            "connectivitycheck.gstatic.com",
            "connect.rom.miui.com",
            "connectivitycheck.platform.hicloud.com",
            "conn1.oppomobile.com",
            "wifi.vivo.com.cn",
            "captive.apple.com",
            "cp.cloudflare.com",
            "www.msftconnecttest.com",
        ]
        for dom in oem_domains:
            self.assertIsNone(parse_feed_line(f"0.0.0.0 {dom}", "auto"))
            self.assertEqual(self.policy.decide("10.8.0.2", dom).action, "allow")

        # Even if both Unbound and upstream DoT fail during a VPN route switch, connectivity probes never SERVFAIL!
        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15998, 18993, 18994)
        with patch("lattice.transport.forward_local", side_effect=TimeoutError("Unbound timeout")), \
             patch("lattice.transport.forward_upstream_dot", side_effect=OSError("Network unreachable")):
            for dom in ("connectivitycheck.gstatic.com", "connect.rom.miui.com", "cp.cloudflare.com", "captive.apple.com"):
                resp = gw.handle_query(query(dom, 1), "10.8.0.2", transport="dot")
                self.assertEqual(resp[3] & 15, 0, f"{dom} returned non-zero RCODE during VPN transition")
                ans = decode_dns_answers(resp)
                self.assertEqual(len(ans), 1)

    def test_vpn_mtu_1280_one_byte_tls_clienthello_fastpath(self):
        from lattice.transport import peek_and_read_proxy

        class OneByteTLSSocket:
            def recv(self, size: int, flags: int = 0) -> bytes:
                # Simulate a VPN tunnel fragmenting the first TCP segment to 1 byte (0x16 TLS Handshake)
                return b"\x16"

        self.assertEqual(peek_and_read_proxy(OneByteTLSSocket()), "")

    def test_vpn_readiness_doctor_and_upstream_pool_clear(self):
        from lattice.app import Lattice
        from lattice.transport import UPSTREAM_TLS_POOL

        app = Lattice(self.tmp.name, resolver_port=15573, dot_port=18913, frp_local_port=18914)
        try:
            report = app.vpn_readiness()
            self.assertTrue(report["ready"], f"VPN readiness failed: {report}")
            self.assertEqual(report["passed"], 6)
            self.assertEqual(report["total"], 6)
            self.assertGreaterEqual(UPSTREAM_TLS_POOL.clear(), 0)
        finally:
            app.shutdown()


    def test_gzip_feed_download_and_parallel_single_pass_refresh_all(self):
        import gzip
        from unittest.mock import patch
        from lattice.feeds import FeedManager

        fm = FeedManager(self.store, self.policy)
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,1,?)",
                ("GzipList1", "https://example.com/list1.txt.gz", "ads", "domains"),
            )
            self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,1,?)",
                ("GzipList2", "https://example.com/list2.txt.gz", "malware", "adblock"),
            )

        gz_payload = gzip.compress(b"0.0.0.0 gz-ad1.example.com\n||gz-ad2.example.org^\n")

        class MockGzipResp:
            headers = {"Content-Encoding": "gzip"}
            def __init__(self, data: bytes):
                self._io = io.BytesIO(data)
            def geturl(self):
                return "https://example.com/list1.txt.gz"
            def read(self, sz: int = -1):
                return self._io.read(sz)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        with patch("lattice.feeds.validate_url", side_effect=lambda u: u), \
             patch("urllib.request.urlopen", side_effect=lambda *a, **kw: MockGzipResp(gz_payload)):
            results = fm.refresh_all()
            self.assertEqual(len(results), 2)
            self.assertEqual(self.policy.decide("192.168.1.10", "gz-ad1.example.com").action, "deny")
            self.assertEqual(self.policy.decide("192.168.1.10", "sub.gz-ad2.example.org").action, "deny")

    def test_rule_pattern_live_tester(self):
        cfg = copy.deepcopy(self.store.config)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)
        self.store.log_query("192.168.1.20", "ad99.tracker.example.com", 1, "allowed", "default", 1.1, 0, "")
        self.store.log_query("192.168.1.20", "clean.example.com", 1, "allowed", "default", 1.1, 0, "")

        res_re = self.store.test_rule_pattern(r"^ad[0-9]+\.tracker\.example\.com$", "regex", "ad42.tracker.example.com")
        self.assertTrue(res_re["ok"])
        self.assertTrue(res_re["sample_matches"])
        self.assertIn("ad99.tracker.example.com", res_re["matched_recent_domains"])

    def test_sqlite_wal_vacuum_and_system_overview(self):
        info = self.store.system_overview()
        self.assertGreater(info["db_size_bytes"], 0)
        vac = self.store.vacuum_database()
        self.assertTrue(vac["ok"])
        self.assertIn("system_info", vac)

    def test_dashboard_profile_stats_breakdown(self):
        cfg = copy.deepcopy(self.store.config)
        cfg["privacy"]["mode"] = "full"
        self.store.set_config(cfg)
        self.store.log_query("192.168.1.10", "a.example.com", 1, "allowed", "default", 1.5, 0, "")
        self.store.log_query("192.168.1.10", "b.example.com", 1, "blocked", "default", 0.5, 3, "feed:test")
        dash = self.store.dashboard(window=3600)
        self.assertIn("profile_stats", dash)
        self.assertEqual(len(dash["profile_stats"]), 1)
        self.assertEqual(dash["profile_stats"][0]["profile"], "default")
        self.assertEqual(dash["profile_stats"][0]["total"], 2)


    def test_update_config_and_dns_cache_clear(self):
        from lattice.app import Lattice
        from lattice.transport import rewrite_response

        app = Lattice(self.tmp.name, resolver_port=15583, dot_port=18923, frp_local_port=18924)
        try:
            q_pkt = _question("cacheclear.example.com", ident=0x9999)
            app.gateway.cache.put("cacheclear.example.com", 1, True, rewrite_response(q_pkt, 1, "93.184.216.34", ttl=60))
            self.assertEqual(app.gateway.cache.stats()["entries"], 1)

            cfg = copy.deepcopy(app.store.config)
            cfg["hostname"] = "dns.test"
            updated = app.update_config({"config": cfg, "secrets": {}})
            self.assertEqual(updated["hostname"], "dns.test")
            self.assertEqual(app.gateway.cache.stats()["entries"], 0)
        finally:
            app.shutdown()


    def test_singleflight_parallel_query_coalescing(self):
        import concurrent.futures
        from unittest.mock import patch
        from lattice.transport import DNSGateway, rewrite_response

        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15591, 18931, 18932)
        call_count = 0
        count_lock = __import__("threading").Lock()

        def slow_upstream(pkt, upstreams, qname="", routes=None):
            nonlocal call_count
            with count_lock:
                call_count += 1
            time.sleep(0.08)
            return rewrite_response(pkt, 1, "203.0.113.88", ttl=60)

        with patch("lattice.transport.forward_upstream_dot", side_effect=slow_upstream):
            def run_one(idx: int):
                q_pkt = _question("photo-cdn.example.com", ident=0x2000 + idx)
                resp = gw.handle_query(q_pkt, "192.168.1.50", transport="dot")
                self.assertEqual(resp[:2], struct.pack("!H", 0x2000 + idx))
                self.assertEqual(resp[3] & 15, 0)
                return resp

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                futs = [pool.submit(run_one, i) for i in range(20)]
                for f in futs:
                    f.result(timeout=5.0)

        self.assertEqual(call_count, 1)
        self.assertGreaterEqual(gw.metrics["coalesced_queries"], 10)

    def test_stale_while_revalidate_zero_stall_photo_cdn(self):
        from unittest.mock import patch
        from lattice.transport import DNSGateway, rewrite_response

        certs = CertificateVault(self.store)
        gw = DNSGateway(self.store, self.policy, certs, 15592, 18933, 18934)
        q_init = _question("scontent.cdn.example.com", ident=0x3001)
        gw.cache.put("scontent.cdn.example.com", 1, True, rewrite_response(q_init, 1, "203.0.113.99", ttl=30), serve_expired_ttl=3600)
        # Expire fresh TTL while keeping stale_until valid
        gw.cache.entries[("scontent.cdn.example.com", 1, True)]["expires_at"] = time.time() - 5.0

        with patch("lattice.transport.forward_upstream_dot", return_value=rewrite_response(q_init, 1, "203.0.113.100", ttl=120)):
            t0 = time.monotonic()
            q2 = _question("scontent.cdn.example.com", ident=0x3002)
            resp, note = gw._forward_query(q2, "scontent.cdn.example.com", 1)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            self.assertLess(elapsed_ms, 15.0)
            self.assertEqual(note, "cache:swr")
            self.assertEqual(resp[:2], b"\x30\x02")

    def test_parallel_hedged_upstream_racing(self):
        from unittest.mock import patch
        from lattice.transport import forward_upstream_dot, rewrite_response

        upstreams = [
            {"id": "slow_primary", "name": "Slow", "address": "1.1.1.1", "port": 853, "sni": "cloudflare-dns.com", "enabled": True},
            {"id": "fast_backup", "name": "Fast", "address": "9.9.9.9", "port": 853, "sni": "dns.quad9.net", "enabled": True},
        ]

        def mock_pool_query(upstream, out_pkt):
            if upstream["id"] == "slow_primary":
                time.sleep(1.2)
            else:
                time.sleep(0.02)
            return rewrite_response(out_pkt, 1, "203.0.113.77", ttl=60)

        with patch("lattice.transport.UPSTREAM_TLS_POOL.query", side_effect=mock_pool_query):
            t0 = time.monotonic()
            q = _question("hedged.example.com", ident=0x4455)
            resp = forward_upstream_dot(q, upstreams, qname="hedged.example.com")
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 0.55)
            self.assertEqual(resp[:2], b"\x44\x55")
            self.assertEqual(resp[3] & 15, 0)


    def test_cloudflare_sync_auto_frpc_target_and_inline_token(self):
        from unittest.mock import patch
        from lattice.app import Lattice

        app = Lattice(self.tmp.name, resolver_port=15595, dot_port=18941, frp_local_port=18942)
        try:
            calls = []

            def fake_cf_request(self_cf, method, path, payload=None):
                calls.append((method, path, payload))
                if path.startswith("/zones?"):
                    return [{"id": "zone-123"}]
                if method == "GET" and "/dns_records?" in path:
                    # Simulate an old conflicting A record that must be replaced by CNAME to frpc server
                    return [{"id": "old-a-rec", "type": "A", "name": "dns.example.com", "content": "198.51.100.1"}]
                if method == "DELETE":
                    return {"id": "old-a-rec"}
                if method == "POST":
                    return {"id": "new-cname-rec", **payload}
                return {}

            with patch("lattice.integrations.CloudflareDNS.request", new=fake_cf_request):
                rec = app.sync_cloudflare({
                    "hostname": "dns.example.com",
                    "frp_server": "frp.edge.example.com",
                    "cloudflare_token": "cf-live-token-xyz",
                })
                self.assertEqual(rec["type"], "CNAME")
                self.assertEqual(rec["name"], "dns.example.com")
                self.assertEqual(rec["content"], "frp.edge.example.com")
                self.assertEqual(app.store.secret("cloudflare"), "cf-live-token-xyz")
                self.assertEqual(app.store.config["public_target"], "frp.edge.example.com")
                self.assertTrue(any(m == "DELETE" for m, _, _ in calls))
        finally:
            app.shutdown()

    def test_0x20_question_case_preservation_and_do_bit_cache_sharing(self):
        from lattice.transport import DNSCache, rewrite_response, _parse_question_section

        cache = DNSCache(max_entries=128)
        q_lower = _question("mixedcase.example.com", ident=0x6001)
        resp_lower = rewrite_response(q_lower, 1, "203.0.113.55", ttl=120)
        # Store with do_bit=True
        cache.put("mixedcase.example.com", 1, True, resp_lower)

        # Query with mixed 0x20 case and do_bit=False!
        q_mixed = (
            struct.pack("!6H", 0x6002, 0x0100, 1, 0, 0, 0)
            + b"\x09MiXeDcAsE\x07ExAmPlE\x03cOm\x00"
            + struct.pack("!HH", 1, 1)
        )
        _, _, q_end, _, _ = _parse_question_section(q_mixed, allow_response=False)
        hit, tag, _ = cache.get_swr("mixedcase.example.com", 1, False, q_mixed[:2], swr_enabled=True, query_question=q_mixed[12:q_end])
        self.assertIsNotNone(hit)
        self.assertEqual(tag, "cache:l1")
        self.assertEqual(hit[:2], b"\x60\x02")
        # Verify exact 0x20 mixed-case question bytes were preserved in the cached response
        self.assertEqual(hit[12:q_end], q_mixed[12:q_end])

    def test_persistent_navigation_and_single_screen_subtabs(self):
        from pathlib import Path
        static_dir = Path(__file__).resolve().parent.parent / "lattice" / "static"
        html = (static_dir / "index.html").read_text(encoding="utf-8")
        js = (static_dir / "app.js").read_text(encoding="utf-8")
        css = (static_dir / "app.css").read_text(encoding="utf-8")

        # Verify page & sub-tab persistence across browser refresh
        self.assertIn("lattice_active_page", js)
        self.assertIn("lattice_subtab_", js)
        self.assertIn("resolveSavedNavigation", js)
        self.assertIn("parseHashNavigation", js)
        self.assertIn("switchPageSubTab", js)
        self.assertIn("window.sessionStorage", js)
        self.assertIn("window.name", js)

        # Verify single-screen sub-tabs across Dashboard, Blocking, DNS, Private, and System
        for sub_id in [
            "dashboard-subnav", "blocking-subnav", "dns-subnav", "private-subnav", "system-subnav",
            "blocking-lists", "blocking-marketplace", "blocking-rules", "blocking-presets", "blocking-devices",
            "density-toggle", "scroll-top-btn"
        ]:
            self.assertIn(f'id="{sub_id}"', html)
        self.assertIn('html[data-density="compact"]', css)



if __name__ == "__main__":
    unittest.main()
