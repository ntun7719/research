"""Configuration model and strict validation for Lattice DNS."""
from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")

DEFAULT_CONFIG: dict[str, Any] = {
    "hostname": "",
    "email": "",
    "public_target": "",
    "dnssec": True,
    "edns_buffer_size": 1232,
    "block_response": "nxdomain",
    "block_custom_ip": "",
    "block_ttl": 30,
    "safesearch": False,
    "rebinding_protection": True,
    "block_doh_canary": True,
    "block_risky_tlds": False,
    "block_punycode": False,
    "doh_enabled": True,
    "privacy": {"mode": "balanced", "retention_days": 7},
    "cache": {
        "rrset_mb": 96,
        "message_mb": 48,
        "prefetch": True,
        "serve_expired": True,
        "serve_expired_ttl": 3600,
    },
    "upstreams": [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "address": "1.1.1.1",
            "port": 853,
            "sni": "cloudflare-dns.com",
            "enabled": True,
        },
        {
            "id": "quad9",
            "name": "Quad9",
            "address": "9.9.9.9",
            "port": 853,
            "sni": "dns.quad9.net",
            "enabled": True,
        },
    ],
    "routes": [],
    "local_records": [],
    "profiles": [
        {
            "id": "default",
            "name": "Default",
            "networks": ["0.0.0.0/0", "::/0"],
            "categories": ["ads", "tracking", "malware"],
            "rate_limit": 300,
            "logging": True,
        }
    ],
    "frp": {
        "enabled": False,
        "server": "",
        "port": 7000,
        "remote_port": 853,
        "auth": "none",
        "proxy_name": "lattice-dot",
    },
}


def hostname(value: Any, field: str = "hostname", allow_empty: bool = False) -> str:
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip().rstrip(".").lower()
    if not value and allow_empty:
        return ""
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"{field} is not a valid hostname") from exc
    if len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"{field} is not a valid hostname")
    return value


def target(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("public_target must be text")
    value = value.strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return hostname(value, "public_target")


def integer(value: Any, low: int, high: int, field: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer between {low} and {high}")
    return value


def identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", value):
        raise ValueError(f"{field} must use lowercase letters, numbers, underscore or dash")
    return value


def validate_config(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Configuration must be an object")

    raw = copy.deepcopy(raw)
    if "acme_email" in raw:
        if not raw.get("email"):
            raw["email"] = raw.pop("acme_email")
        else:
            raw.pop("acme_email")
    if "cloudflare" in raw and isinstance(raw["cloudflare"], dict):
        if "dns_target" in raw["cloudflare"] and not raw.get("public_target"):
            raw["public_target"] = raw["cloudflare"]["dns_target"]
        raw.pop("cloudflare", None)
    if "prefetch" in raw:
        val = raw.pop("prefetch")
        if isinstance(raw.get("cache"), dict):
            raw["cache"]["prefetch"] = val
    if "serve_expired" in raw:
        val = raw.pop("serve_expired")
        if isinstance(raw.get("cache"), dict):
            raw["cache"]["serve_expired"] = val

    unknown = set(raw) - set(DEFAULT_CONFIG)
    if unknown:
        raise ValueError("Unknown configuration fields: " + ", ".join(sorted(unknown)))

    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for key, value in raw.items():
        cfg[key] = copy.deepcopy(value)

    cfg["hostname"] = hostname(cfg["hostname"], allow_empty=True)
    if cfg["hostname"] and "." not in cfg["hostname"]:
        raise ValueError("Private DNS hostname must be a public fully qualified name")
    if cfg["email"]:
        if not isinstance(cfg["email"], str) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", cfg["email"]):
            raise ValueError("email must be a valid address")
    cfg["public_target"] = target(cfg["public_target"])
    if type(cfg["dnssec"]) is not bool:
        raise ValueError("dnssec must be true or false")
    cfg["edns_buffer_size"] = integer(cfg["edns_buffer_size"], 512, 4096, "edns_buffer_size")
    cfg["safesearch"] = bool(cfg.get("safesearch", False))
    cfg["rebinding_protection"] = bool(cfg.get("rebinding_protection", True))
    cfg["block_doh_canary"] = bool(cfg.get("block_doh_canary", True))
    cfg["block_risky_tlds"] = bool(cfg.get("block_risky_tlds", False))
    cfg["block_punycode"] = bool(cfg.get("block_punycode", False))
    cfg["doh_enabled"] = bool(cfg.get("doh_enabled", True))
    if cfg["block_response"] not in ("nxdomain", "refused", "zero", "custom_ip"):
        raise ValueError("block_response must be nxdomain, refused, zero or custom_ip")
    cfg["block_ttl"] = integer(int(cfg.get("block_ttl", 30)), 1, 3600, "block_ttl")
    raw_custom_ip = str(cfg.get("block_custom_ip", "") or "").strip()
    if raw_custom_ip:
        try:
            cfg["block_custom_ip"] = str(ipaddress.ip_address(raw_custom_ip))
        except ValueError as exc:
            raise ValueError("block_custom_ip must be a valid IPv4 or IPv6 address") from exc
    else:
        cfg["block_custom_ip"] = "0.0.0.0" if cfg["block_response"] == "custom_ip" else "" 

    privacy = cfg["privacy"]
    if not isinstance(privacy, dict) or set(privacy) != {"mode", "retention_days"}:
        raise ValueError("privacy must contain mode and retention_days")
    if privacy["mode"] not in ("full", "balanced", "minimal"):
        raise ValueError("privacy mode must be full, balanced or minimal")
    privacy["retention_days"] = integer(privacy["retention_days"], 1, 90, "retention_days")

    cache = cfg["cache"]
    expected_cache = {"rrset_mb", "message_mb", "prefetch", "serve_expired", "serve_expired_ttl"}
    if not isinstance(cache, dict) or set(cache) != expected_cache:
        raise ValueError("cache settings are incomplete")
    cache["rrset_mb"] = integer(cache["rrset_mb"], 16, 2048, "rrset_mb")
    cache["message_mb"] = integer(cache["message_mb"], 8, 1024, "message_mb")
    cache["serve_expired_ttl"] = integer(cache["serve_expired_ttl"], 60, 86400, "serve_expired_ttl")
    if type(cache["prefetch"]) is not bool or type(cache["serve_expired"]) is not bool:
        raise ValueError("cache booleans are invalid")

    upstreams = cfg["upstreams"]
    if not isinstance(upstreams, list) or not 1 <= len(upstreams) <= 24:
        raise ValueError("Provide between 1 and 24 upstreams")
    seen_upstreams: set[str] = set()
    for item in upstreams:
        if isinstance(item, dict) and "tls_hostname" in item and "sni" not in item:
            item["sni"] = item.pop("tls_hostname")
        elif isinstance(item, dict) and "tls_hostname" in item:
            item.pop("tls_hostname", None)
        required = {"id", "name", "address", "port", "sni", "enabled"}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("Each upstream requires id, name, address, port, sni and enabled")
        item["id"] = identifier(item["id"], "upstream id")
        if item["id"] in seen_upstreams:
            raise ValueError("Duplicate upstream id")
        seen_upstreams.add(item["id"])
        if not isinstance(item["name"], str) or not 1 <= len(item["name"].strip()) <= 80:
            raise ValueError("Upstream name must contain 1 to 80 characters")
        item["name"] = item["name"].strip()
        item["address"] = str(ipaddress.ip_address(item["address"]))
        item["port"] = integer(item["port"], 1, 65535, "upstream port")
        item["sni"] = hostname(item["sni"], "upstream sni")
        if type(item["enabled"]) is not bool:
            raise ValueError("upstream enabled must be true or false")
    enabled_ids = {u["id"] for u in upstreams if u["enabled"]}
    if not enabled_ids:
        raise ValueError("At least one upstream must be enabled")

    local_records = cfg.get("local_records", [])
    if not isinstance(local_records, list) or len(local_records) > 256:
        raise ValueError("Provide at most 256 local_records")
    clean_local = []
    seen_local = set()
    for rec in local_records:
        if not isinstance(rec, dict):
            raise ValueError("Each local record must be an object")
        rec_name = hostname(rec.get("name"), "local record name")
        rec_type = str(rec.get("type", "A")).upper()
        if rec_type not in {"A", "AAAA", "CNAME", "TXT"}:
            raise ValueError(f"Unsupported record type {rec_type}, must be A, AAAA, CNAME, or TXT")
        rec_val = str(rec.get("value", "")).strip()
        if rec_type == "A":
            rec_val = str(ipaddress.IPv4Address(rec_val))
        elif rec_type == "AAAA":
            rec_val = str(ipaddress.IPv6Address(rec_val))
        elif rec_type == "CNAME":
            rec_val = hostname(rec_val, "cname target")
        elif rec_type == "TXT":
            rec_val = rec_val.replace('"', "").replace("\n", " ").replace("\r", " ").strip()
            if not rec_val or len(rec_val) > 255:
                raise ValueError("TXT record value must be 1 to 255 characters")
        ttl_val = int(rec.get("ttl", 300))
        if not 1 <= ttl_val <= 86400:
            raise ValueError("Local record TTL must be between 1 and 86400")
        key = (rec_name, rec_type)
        if key in seen_local:
            raise ValueError(f"Duplicate local record: {rec_name} {rec_type}")
        seen_local.add(key)
        clean_local.append({"name": rec_name, "type": rec_type, "value": rec_val, "ttl": ttl_val})
    cfg["local_records"] = clean_local

    routes = cfg["routes"]
    if not isinstance(routes, list) or len(routes) > 64:
        raise ValueError("Provide at most 64 routes")
    seen_routes: set[str] = set()
    for route in routes:
        if not isinstance(route, dict) or set(route) != {"suffix", "upstreams"}:
            raise ValueError("Each route requires suffix and upstreams")
        route["suffix"] = hostname(route["suffix"], "route suffix")
        if route["suffix"] in seen_routes:
            raise ValueError("Duplicate route suffix")
        seen_routes.add(route["suffix"])
        if not isinstance(route["upstreams"], list) or not route["upstreams"]:
            raise ValueError("A route must select at least one upstream")
        if len(set(route["upstreams"])) != len(route["upstreams"]) or any(x not in enabled_ids for x in route["upstreams"]):
            raise ValueError("A route references an unavailable upstream")

    profiles = cfg["profiles"]
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 32:
        raise ValueError("Provide between 1 and 32 client profiles")
    seen_profiles: set[str] = set()
    network_entries = 0
    for profile in profiles:
        if isinstance(profile, dict) and isinstance(profile.get("categories"), dict):
            profile["categories"] = [k for k, v in profile["categories"].items() if v]
        required = {"id", "name", "networks", "categories", "rate_limit", "logging"}
        if not isinstance(profile, dict) or set(profile) != required:
            raise ValueError("Each profile requires id, name, networks, categories, rate_limit and logging")
        profile["id"] = identifier(profile["id"], "profile id")
        if profile["id"] in seen_profiles:
            raise ValueError("Duplicate profile id")
        seen_profiles.add(profile["id"])
        if not isinstance(profile["name"], str) or not 1 <= len(profile["name"].strip()) <= 80:
            raise ValueError("Profile name must contain 1 to 80 characters")
        profile["name"] = profile["name"].strip()
        if not isinstance(profile["networks"], list) or not profile["networks"]:
            raise ValueError("Each profile needs at least one network")
        profile["networks"] = [str(ipaddress.ip_network(n, strict=False)) for n in profile["networks"]]
        network_entries += len(profile["networks"])
        if network_entries > 128:
            raise ValueError("Too many profile network entries")
        if not isinstance(profile["categories"], list) or len(profile["categories"]) > 32:
            raise ValueError("Profile categories are invalid")
        profile["categories"] = sorted({identifier(x, "category") for x in profile["categories"]})
        profile["rate_limit"] = integer(profile["rate_limit"], 1, 10000, "profile rate_limit")
        if type(profile["logging"]) is not bool:
            raise ValueError("profile logging must be true or false")

    frp = cfg["frp"]
    required_frp = {"enabled", "server", "port", "remote_port", "auth", "proxy_name"}
    if not isinstance(frp, dict) or set(frp) != required_frp:
        raise ValueError("FRP settings are incomplete")
    if type(frp["enabled"]) is not bool or frp["auth"] not in ("none", "token"):
        raise ValueError("FRP enabled or authentication mode is invalid")
    frp["server"] = target(frp["server"]) if frp["server"] else ""
    frp["port"] = integer(frp["port"], 1, 65535, "FRP port")
    frp["remote_port"] = integer(frp["remote_port"], 1, 65535, "FRP remote_port")
    frp["proxy_name"] = identifier(frp["proxy_name"], "FRP proxy_name")
    if frp["enabled"] and not frp["server"]:
        raise ValueError("FRP server is required when FRP is enabled")
    if frp["remote_port"] != 853:
        raise ValueError("Android Private DNS requires the public FRP port to be 853")
    if not cfg["public_target"] and frp["server"]:
        cfg["public_target"] = frp["server"]

    return cfg
