"""Compiled client profiles, per-device profile overrides, regex/wildcard rules, fast feed match cache, and Android connectivity safeguards."""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from .config import hostname

# Match only actual Google Search hostnames (e.g. google.com, www.google.com, www.google.com.sg, www.google.co.uk)
# Never hijack Android system subdomains like clients3.google.com, play.google.com, mtalk.google.com, dl.google.com!
GOOGLE_SEARCH_RE = re.compile(r"^(?:www\.)?google\.(?:com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2}|ca|de|fr|it|es|nl|pl|jp|kr|in|au|br|mx)$")

ANDROID_ESSENTIAL_EXACT = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "clients4.google.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
    "www.msftconnecttest.com",
    "ipv4only.arpa",
    "_dns.resolver.arpa",
    "dnsotls-ds.metric.gstatic.com",
}


def is_android_essential(name: str, configured_hostname: str = "") -> bool:
    """Return True if domain is required for Android Private DNS validation or captive portal connectivity."""
    clean = name.strip().lower().rstrip(".")
    if not clean:
        return False
    if configured_hostname and clean == configured_hostname.strip().lower().rstrip("."):
        return True
    if clean in ANDROID_ESSENTIAL_EXACT:
        return True
    if clean.endswith(".dnsotls-ds.metric.gstatic.com"):
        return True
    return False


def get_safesearch_rewrite(name: str) -> tuple[str, str] | None:
    clean = name.strip().lower().rstrip(".")
    if GOOGLE_SEARCH_RE.fullmatch(clean):
        return "216.239.38.120", "safesearch:google"
    if clean in ("youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"):
        return "216.239.38.119", "safesearch:youtube"
    if clean in ("bing.com", "www.bing.com", "cn.bing.com"):
        return "204.79.197.220", "safesearch:bing"
    if clean in ("duckduckgo.com", "www.duckduckgo.com", "safe.duckduckgo.com"):
        return "52.142.124.215", "safesearch:duckduckgo"
    if clean in ("yandex.ru", "www.yandex.ru", "yandex.com", "www.yandex.com"):
        return "213.180.193.56", "safesearch:yandex"
    return None


@dataclass(frozen=True)
class Decision:
    action: str
    source: str
    profile: str
    value: str = ""


class Bloom:
    def __init__(self, bits: int = 1 << 26, hashes: int = 6):
        self.bits = bits
        self.hashes = hashes
        self.data = bytearray(math.ceil(bits / 8))

    def add(self, value: str) -> None:
        value = value.strip().lower()
        digest = hashlib.blake2b(value.encode(), digest_size=32).digest()
        for i in range(self.hashes):
            offset = int.from_bytes(digest[i * 4 : i * 4 + 4], "big") % self.bits
            self.data[offset >> 3] |= 1 << (offset & 7)

    def maybe(self, value: str) -> bool:
        value = value.strip().lower()
        digest = hashlib.blake2b(value.encode(), digest_size=32).digest()
        for i in range(self.hashes):
            offset = int.from_bytes(digest[i * 4 : i * 4 + 4], "big") % self.bits
            if not self.data[offset >> 3] & (1 << (offset & 7)):
                return False
        return True


class Policy:
    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.profile_networks: list[tuple[ipaddress._BaseNetwork, dict[str, Any]]] = []
        self.device_profiles: dict[str, dict[str, Any]] = {}
        self.rules: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.regex_rules: list[tuple[str, re.Pattern[str], dict[str, Any]]] = []
        self.bloom = Bloom()
        self._match_cache: dict[tuple[str, tuple[str, ...]], tuple[str, str] | None] = {}
        self.feed_count = 0
        self.compile()

    def compile(self) -> None:
        cfg = self.store.config
        profile_by_id = {p["id"]: p for p in cfg["profiles"]}
        networks: list[tuple[ipaddress._BaseNetwork, dict[str, Any]]] = []
        for profile in cfg["profiles"]:
            for network in profile["networks"]:
                networks.append((ipaddress.ip_network(network), profile))
        networks.sort(key=lambda pair: pair[0].prefixlen, reverse=True)

        device_map: dict[str, dict[str, Any]] = {}
        for dev in self.store.get_devices():
            prof_id = dev.get("profile", "*")
            if prof_id and prof_id != "*" and prof_id in profile_by_id:
                device_map[dev["ip"]] = profile_by_id[prof_id]

        rules: dict[tuple[str, str, str], dict[str, Any]] = {}
        regex_list: list[tuple[str, re.Pattern[str], dict[str, Any]]] = []
        for row in self.store.rule_rows():
            if row["kind"] == "regex":
                try:
                    regex_list.append((row["profile"], re.compile(row["pattern"], re.IGNORECASE), row))
                except re.error:
                    pass
            else:
                rules[(row["profile"], row["kind"], row["pattern"])] = row

        bloom = Bloom()
        count = 0
        with self.store.lock:
            query = (
                "SELECT DISTINCT fd.domain FROM feed_domains fd "
                "JOIN feeds f ON f.id=fd.feed_id WHERE f.enabled=1"
            )
            for row in self.store.db.execute(query):
                bloom.add(row["domain"])
                count += 1

        with self.lock:
            self.profile_networks = networks
            self.device_profiles = device_map
            self.rules = rules
            self.regex_rules = regex_list
            self.bloom = bloom
            self._match_cache.clear()
            self.feed_count = count

    def profile(self, client: str) -> dict[str, Any]:
        norm_client = client
        try:
            address = ipaddress.ip_address(client)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            norm_client = str(address)
        except ValueError:
            with self.lock:
                if norm_client in self.device_profiles:
                    return self.device_profiles[norm_client]
            return self.store.config["profiles"][0]
        with self.lock:
            if norm_client in self.device_profiles:
                return self.device_profiles[norm_client]
            for network, profile in self.profile_networks:
                if address in network:
                    return profile
        return self.store.config["profiles"][0]

    @staticmethod
    def parents(name: str) -> list[str]:
        if not name:
            return []
        labels = [l for l in name.split(".") if l]
        return [".".join(labels[i:]) for i in range(len(labels))]

    def _rule(self, profile_id: str, name: str) -> dict[str, Any] | None:
        if not name:
            return None
        now = time.time()
        parents = self.parents(name)
        with self.lock:
            for scope in (profile_id, "*"):
                row = self.rules.get((scope, "exact", name))
                if row and (row["expires"] is None or row["expires"] > now):
                    return row
                for suffix in parents:
                    row = self.rules.get((scope, "suffix", suffix))
                    if row and (row["expires"] is None or row["expires"] > now):
                        return row
                for r_scope, compiled_re, r_row in self.regex_rules:
                    if r_scope == scope and (r_row["expires"] is None or r_row["expires"] > now):
                        if compiled_re.search(name):
                            return r_row
        return None

    def _feed_match(self, name: str, categories: list[str]) -> tuple[str, str] | None:
        if not name or not categories:
            return None
        if is_android_essential(name, self.store.config.get("hostname", "")):
            return None
        cat_key = tuple(categories)
        cache_key = (name, cat_key)
        with self.lock:
            if cache_key in self._match_cache:
                return self._match_cache[cache_key]
            bloom = self.bloom
        candidates = self.parents(name)
        possible = [candidate for candidate in candidates if bloom.maybe(candidate)]
        if not possible:
            with self.lock:
                if len(self._match_cache) < 16384:
                    self._match_cache[cache_key] = None
            return None
        placeholders_domains = ",".join("?" for _ in possible)
        placeholders_categories = ",".join("?" for _ in categories)
        query = (
            "SELECT fd.domain,fd.category,f.name FROM feed_domains fd "
            "JOIN feeds f ON f.id=fd.feed_id "
            f"WHERE f.enabled=1 AND fd.domain IN ({placeholders_domains}) "
            f"AND fd.category IN ({placeholders_categories}) LIMIT 1"
        )
        with self.store.lock:
            row = self.store.db.execute(query, tuple(possible + categories)).fetchone()
        result = (row["domain"], row["name"]) if row else None
        with self.lock:
            if len(self._match_cache) < 16384:
                self._match_cache[cache_key] = result
        return result

    def decide(self, client: str, name: str) -> Decision:
        try:
            name = hostname(name, "query hostname", allow_empty=True)
        except ValueError:
            return Decision("deny", "policy:malformed", "default")
        profile = self.profile(client)
        if not name:
            return Decision("allow", "policy:root", profile["id"])
        row = self._rule(profile["id"], name)
        if row:
            if row["action"] == "rewrite":
                return Decision(row["action"], f"rule:{row['id']}", profile["id"], row["value"])
            if row["action"] == "allow":
                return Decision("allow", f"rule:{row['id']}", profile["id"], row["value"])
            if not self.store.is_blocking_paused():
                return Decision(row["action"], f"rule:{row['id']}", profile["id"], row["value"])
        if self.store.is_blocking_paused():
            return Decision("allow", "policy:snoozed", profile["id"])
        if self.store.config.get("safesearch", False):
            ss = get_safesearch_rewrite(name)
            if ss:
                target_ip, engine = ss
                return Decision("rewrite", engine, profile["id"], target_ip)
        match = self._feed_match(name, profile["categories"])
        if match:
            domain, feed = match
            return Decision("deny", f"feed:{feed}:{domain}", profile["id"])
        return Decision("allow", "policy:default", profile["id"])

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "profiles": len(self.store.config["profiles"]),
                "device_overrides": len(self.device_profiles),
                "rules": len(self.rules) + len(self.regex_rules),
                "regex_rules": len(self.regex_rules),
                "indexed_domains": self.feed_count,
            }


IGNORE_FEED_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "dnsotls-ds.metric.gstatic.com",
    "ipv4only.arpa",
    "_dns.resolver.arpa",
}


def parse_feed_line(line: str, mode: str = "auto") -> str | None:
    text = line.split("#", 1)[0].split("!", 1)[0].strip()
    if not text or text.startswith("["):
        return None
    if mode in ("auto", "adblock"):
        if text.startswith("@@"):
            return None
        if text.startswith("||"):
            text = text[2:].split("^", 1)[0].split("$", 1)[0].split("/", 1)[0]
        elif any(token in text for token in ("/", "?", "*")) and not re.match(r"^\d+\.\d+\.\d+\.\d+\s+", text):
            if mode == "adblock":
                return None
    if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+", text):
        parts = text.split()
        if len(parts) < 2:
            return None
        text = parts[1]
    text = text.lstrip("*.").rstrip(".").lower()
    if not text or text in IGNORE_FEED_DOMAINS:
        return None
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass
    try:
        return hostname(text, "feed domain")
    except ValueError:
        return None
