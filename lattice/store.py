"""Persistent state, encrypted secrets, non-blocking query telemetry queue, 12 service presets, and authentication."""
from __future__ import annotations

import base64
import collections
import copy
import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from .config import DEFAULT_CONFIG, hostname, validate_config

DEFAULT_SCHEDULE = {
    "enabled": False,
    "mode": "bedtime",
    "start": "22:00",
    "end": "07:00",
    "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
    "presets": ["tiktok", "meta", "youtube", "gaming", "snapchat", "reddit"],
    "categories": ["social", "adult"],
    "profile": "*",
}



def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


PRESETS: dict[str, dict[str, Any]] = {
    "tiktok": {
        "name": "TikTok & ByteDance",
        "group": "social",
        "description": "Short-form video app, CDN nodes, and telemetry endpoints",
        "domains": ["tiktok.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com", "musical.ly", "tiktokv.com"],
    },
    "meta": {
        "name": "Meta Social Suite",
        "group": "social",
        "description": "Facebook, Instagram, Threads, WhatsApp, and Meta graph beacons",
        "domains": ["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "threads.net", "whatsapp.com", "meta.com"],
    },
    "youtube": {
        "name": "YouTube & Video Delivery",
        "group": "streaming",
        "description": "YouTube web, mobile APIs, Shorts, and Google video streaming CDNs",
        "domains": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com", "youtube-nocookie.com"],
    },
    "discord": {
        "name": "Discord Voice & Chat",
        "group": "social",
        "description": "Discord messaging client, media attachments, and voice gateway servers",
        "domains": ["discord.com", "discordapp.com", "discordapp.net", "discord.gg", "discord.media", "discordcdn.com"],
    },
    "twitter": {
        "name": "X (Twitter) & Media",
        "group": "social",
        "description": "X/Twitter timeline, API endpoints, t.co shortlinks, and video/image CDNs",
        "domains": ["twitter.com", "x.com", "twimg.com", "t.co", "vine.co", "periscope.tv"],
    },
    "snapchat": {
        "name": "Snapchat & Bitmoji",
        "group": "social",
        "description": "Snapchat messaging, Spotlight media delivery, and Bitmoji avatars",
        "domains": ["snapchat.com", "sc-cdn.net", "snap-dev.net", "bitmoji.com", "snapads.com"],
    },
    "netflix": {
        "name": "Netflix Streaming",
        "group": "streaming",
        "description": "Netflix video streaming, OpenConnect CDNs, and Fast.com probes",
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com", "fast.com"],
    },
    "reddit": {
        "name": "Reddit & Media",
        "group": "social",
        "description": "Reddit forums, mobile APIs, redd.it media hosts, and analytics",
        "domains": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "redditinc.com"],
    },
    "gaming": {
        "name": "Gaming Platforms",
        "group": "gaming_ai",
        "description": "Steam, Roblox, Epic Games, Battle.net, and Riot storefront/matchmaking",
        "domains": ["steampowered.com", "steamcommunity.com", "roblox.com", "rbxcdn.com", "epicgames.com", "riotgames.com", "battle.net"],
    },
    "ai_bots": {
        "name": "Generative AI Portals",
        "group": "gaming_ai",
        "description": "ChatGPT, OpenAI API, Claude, Perplexity, and Character.AI web access",
        "domains": ["chatgpt.com", "openai.com", "oaistatic.com", "claude.ai", "anthropic.com", "perplexity.ai", "character.ai"],
    },
    "cryptominers": {
        "name": "Cryptocurrency Web Miners",
        "group": "security",
        "description": "Browser-based coin mining scripts, Stratum pools, and cryptojacking relays",
        "domains": ["coinhive.com", "crypto-loot.com", "minergate.com", "coin-have.com", "jsecoin.com", "nanopool.org", "2miners.com"],
    },
    "telemetry": {
        "name": "OS, Mobile & Smart-TV Telemetry",
        "group": "security",
        "description": "Windows, Samsung, Xiaomi, Roku, and LG ACR background telemetry beacons",
        "domains": [
            "v10.events.data.microsoft.com",
            "telemetry.microsoft.com",
            "settings-win.data.microsoft.com",
            "watson.telemetry.microsoft.com",
            "samsungads.com",
            "samsungelectronics.com",
            "tracking.miui.com",
            "data.mistat.xiaomi.com",
            "scribe.logs.roku.com",
            "lgad.cjpowercast.com",
        ],
    },
    "telegram": {
        "name": "Telegram Messenger & CDN",
        "group": "social",
        "description": "Telegram mobile/desktop messaging clients, t.me links, and media relays",
        "domains": ["telegram.org", "t.me", "tdesktop.com", "telegra.ph", "telegram.me", "telesco.pe"],
    },
    "twitch": {
        "name": "Twitch Live Streaming",
        "group": "streaming",
        "description": "Twitch live video channels, chat relays, and ttvnw video edge CDNs",
        "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net"],
    },
    "spotify": {
        "name": "Spotify Music & Podcasts",
        "group": "streaming",
        "description": "Spotify audio streaming, desktop/mobile apps, and scdn media delivery",
        "domains": ["spotify.com", "scdn.co", "spotifycdn.com", "pscdn.co", "spoti.fi"],
    },
    "disney_prime": {
        "name": "Disney+ & Prime Video",
        "group": "streaming",
        "description": "Disney+, BAMGrid streaming infrastructure, and Amazon Prime Video CDNs",
        "domains": ["disneyplus.com", "bamgrid.com", "dssott.com", "primevideo.com", "aiv-cdn.net"],
    },
    "pinterest": {
        "name": "Pinterest & Visual Feed",
        "group": "social",
        "description": "Pinterest boards, pinimg image CDNs, and shortlinks",
        "domains": ["pinterest.com", "pinimg.com", "pin.it", "pinterest.co.uk", "pinterest.de"],
    },
    "dating": {
        "name": "Dating Apps (Tinder, Bumble, Hinge)",
        "group": "adult_betting",
        "description": "Tinder, Bumble, Hinge, Badoo, OkCupid, and Match mobile/web endpoints",
        "domains": ["tinder.com", "gotinder.com", "bumble.com", "hinge.co", "badoo.com", "okcupid.com", "match.com"],
    },
    "gambling_bet": {
        "name": "Online Betting & Casinos",
        "group": "adult_betting",
        "description": "Bet365, DraftKings, FanDuel, Stake, 1xBet, and online casino platforms",
        "domains": ["bet365.com", "draftkings.com", "fanduel.com", "stake.com", "1xbet.com", "betway.com", "pokerstars.com"],
    },
    "doh_bypass": {
        "name": "Public DoH Bypass Resolvers",
        "group": "security",
        "description": "Block third-party browser DoH endpoints so devices cannot bypass Lattice policies",
        "domains": ["dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "doh.opendns.com", "dns.nextdns.io", "use-application-dns.net"],
    },
    "whatsapp": {
        "name": "WhatsApp Messenger & Calls",
        "group": "social",
        "description": "WhatsApp messaging, voice/video calling relays, and media attachment servers",
        "domains": ["whatsapp.com", "whatsapp.net", "wa.me", "whatsapp-plus.info"],
    },
    "signal": {
        "name": "Signal Private Messenger",
        "group": "social",
        "description": "Signal desktop/mobile encrypted messaging, voice relays, and whispersystems CDNs",
        "domains": ["signal.org", "whispersystems.org", "signal.art", "signal.link"],
    },
    "ebay_shopping": {
        "name": "Temu, Shein & Flash Shopping",
        "group": "adult_betting",
        "description": "Temu, Shein, and AliExpress shopping apps, gamified promos, and ad-tracking CDNs",
        "domains": ["temu.com", "kwcdn.com", "shein.com", "ltwebstatic.com", "aliexpress.com"],
    },
    "smart_tv_acr": {
        "name": "Smart-TV ACR & Ad Overlays",
        "group": "security",
        "description": "Automatic Content Recognition (ACR) frame-grabbers on LG, Samsung, Roku, and Vizio TVs",
        "domains": ["samsungads.com", "samsungacr.com", "lgad.cjpowercast.com", "ads.roku.com", "cognitivetv.com", "inscape.tv"],
    },
}

RECOMMENDED_FEED_BUNDLE: list[dict[str, str]] = [
    {
        "name": "StevenBlack Unified Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "ads",
        "format": "domains",
    },
    {
        "name": "AdGuard SDN DNS Filter",
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "category": "ads",
        "format": "adblock",
    },
    {
        "name": "URLHaus Abuse.ch Malware Hostfile",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "category": "malware",
        "format": "domains",
    },
    {
        "name": "Peter Lowe Ad & Tracker Servers",
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
        "category": "tracking",
        "format": "domains",
    },
]

CURATED_BLOCKLIST_CATALOG: list[dict[str, Any]] = [
    {
        "id": "stevenblack_unified",
        "name": "StevenBlack Unified Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "ads",
        "format": "domains",
        "scale": "~130k domains",
        "description": "Gold-standard consolidated hosts file merging adware, mobile ads, and mainstream tracker networks.",
        "packs": ["core", "privacy"],
    },
    {
        "id": "adguard_sdn",
        "name": "AdGuard SDN DNS Filter",
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "category": "ads",
        "format": "adblock",
        "scale": "~65k rules",
        "description": "AdGuard official DNS filter compiled from English, Mobile Ads, Spyware, and AdGuard Base lists.",
        "packs": ["core", "privacy"],
    },
    {
        "id": "oisd_small",
        "name": "OISD Small (Zero-Breakage Core)",
        "url": "https://small.oisd.nl/domainswild2",
        "category": "ads",
        "format": "domains",
        "scale": "~70k domains",
        "description": "Curated low-false-positive ad and tracker blocklist engineered so apps and websites never break.",
        "packs": ["privacy", "family"],
    },
    {
        "id": "oisd_big",
        "name": "OISD Big (Full Spectrum Blocklist)",
        "url": "https://big.oisd.nl/domainswild2",
        "category": "ads",
        "format": "domains",
        "scale": "~280k domains",
        "description": "Comprehensive OISD protection combining ads, trackers, telemetry, phishing, and scam networks.",
        "packs": ["privacy"],
    },
    {
        "id": "hagezi_pro",
        "name": "HaGeZi Multi PRO Blocklist",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "category": "ads",
        "format": "domains",
        "scale": "~240k domains",
        "description": "Balanced multi-source broom cleaning ads, affiliate tracking, telemetry, scam, and malware domains.",
        "packs": ["privacy"],
    },
    {
        "id": "hagezi_tif",
        "name": "HaGeZi Threat Intelligence Feeds (TIF)",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "category": "malware",
        "format": "domains",
        "scale": "~450k domains",
        "description": "High-coverage threat intelligence feed blocking active botnet C2, malware drops, and phishing hosts.",
        "packs": ["malware"],
    },
    {
        "id": "hagezi_native",
        "name": "HaGeZi Native OS & Device Trackers",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.winoffice.txt",
        "category": "tracking",
        "format": "domains",
        "scale": "~2k domains",
        "description": "Blocks native background telemetry in Windows, Microsoft Office, and connected consumer devices.",
        "packs": ["privacy"],
    },
    {
        "id": "peter_lowe",
        "name": "Peter Lowe Ad & Tracker Servers",
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
        "category": "tracking",
        "format": "domains",
        "scale": "~3.6k domains",
        "description": "Hand-maintained, zero-false-positive list of persistent advertising and user-tracking servers.",
        "packs": ["core", "privacy"],
    },
    {
        "id": "firebog_easyprivacy",
        "name": "EasyPrivacy DNS Trackers (Firebog)",
        "url": "https://v.firebog.net/hosts/Easyprivacy.txt",
        "category": "tracking",
        "format": "domains",
        "scale": "~38k domains",
        "description": "Parsed DNS hostfile from EasyPrivacy targeting web bugs, heatmaps, and fingerprinting scripts.",
        "packs": ["privacy"],
    },
    {
        "id": "frogeye_firstparty",
        "name": "First-Party & CNAME Trackers (Frogeye)",
        "url": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
        "category": "tracking",
        "format": "domains",
        "scale": "~12k domains",
        "description": "Targets disguised CNAME-cloaked trackers (Eulerian, Pardot, Criteo, Adobe) hiding on first-party domains.",
        "packs": ["privacy"],
    },
    {
        "id": "urlhaus_malware",
        "name": "URLHaus Abuse.ch Malware Hostfile",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "category": "malware",
        "format": "domains",
        "scale": "~15k domains",
        "description": "Real-time feed from Abuse.ch URLHaus blocking sites actively distributing malware payloads.",
        "packs": ["core", "malware", "family"],
    },
    {
        "id": "phishing_army",
        "name": "Phishing Army Extended Blocklist",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "category": "malware",
        "format": "domains",
        "scale": "~140k domains",
        "description": "Aggregated phishing intelligence feed from PhishTank, OpenPhish, and CertStream credential lures.",
        "packs": ["malware", "family"],
    },
    {
        "id": "dandelion_antimalware",
        "name": "DandelionSprout Anti-Malware List",
        "url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareDomains.txt",
        "category": "malware",
        "format": "domains",
        "scale": "~25k domains",
        "description": "Curated protection against ransomware, fake software updaters, trojan droppers, and scam domains.",
        "packs": ["malware"],
    },
    {
        "id": "spam404_scams",
        "name": "Spam404 Fraud & Tech-Scam Blacklist",
        "url": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        "category": "malware",
        "format": "domains",
        "scale": "~8k domains",
        "description": "Blocks known financial fraud, deceptive popups, fake giveaway lures, and tech-support scams.",
        "packs": ["malware"],
    },
    {
        "id": "nocoin_miners",
        "name": "NoCoin Browser Cryptomining Filter",
        "url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "category": "malware",
        "format": "domains",
        "scale": "~1k domains",
        "description": "Stops WebAssembly and JavaScript browser cryptojacking scripts and mining pool relays.",
        "packs": ["malware"],
    },
    {
        "id": "stevenblack_porn",
        "name": "StevenBlack Adult & Pornography Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
        "category": "adult",
        "format": "domains",
        "scale": "~140k domains",
        "description": "Dedicated adult content blocklist for family networks, schools, and parental-control profiles.",
        "packs": ["family"],
    },
    {
        "id": "stevenblack_gambling",
        "name": "StevenBlack Gambling & Casino Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
        "category": "custom",
        "format": "domains",
        "scale": "~15k domains",
        "description": "Blocks online casinos, sportsbooks, betting exchanges, and lottery/wagering portals.",
        "packs": ["family"],
    },
    {
        "id": "stevenblack_social",
        "name": "StevenBlack Social Networks Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
        "category": "social",
        "format": "domains",
        "scale": "~5k domains",
        "description": "Comprehensive social media network hostfile for deep focus or restricted workplace environments.",
        "packs": [],
    },
    {
        "id": "hagezi_light",
        "name": "HaGeZi Multi LIGHT Blocklist",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
        "category": "ads",
        "format": "domains",
        "scale": "~90k domains",
        "description": "Lightweight, ultra-safe baseline ad, tracking, and scam filter suitable for shared family routers.",
        "packs": ["family"],
    },
    {
        "id": "hagezi_ultimate",
        "name": "HaGeZi Multi ULTIMATE Blocklist",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
        "category": "ads",
        "format": "domains",
        "scale": "~420k domains",
        "description": "Aggressive maximum-hardening DNS shield purging ads, affiliate links, telemetry, and CNAME trackers.",
        "packs": ["privacy"],
    },
    {
        "id": "hagezi_apple_native",
        "name": "HaGeZi Apple iOS & macOS Native Tracker Guard",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.apple.txt",
        "category": "tracking",
        "format": "domains",
        "scale": "~500 domains",
        "description": "Blocks background Apple iOS, iPadOS, and macOS diagnostics and telemetry without breaking iCloud.",
        "packs": ["privacy"],
    },
    {
        "id": "hagezi_samsung_xiaomi",
        "name": "HaGeZi Xiaomi, Realme & Oppo Native Telemetry",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.xiaomi.txt",
        "category": "tracking",
        "format": "domains",
        "scale": "~1.2k domains",
        "description": "Stops aggressive OS-level background analytics and ad beacons on MIUI/HyperOS and Android OEM phones.",
        "packs": ["privacy"],
    },
    {
        "id": "stalkerware_indicators",
        "name": "AssoEchap Stalkerware & Spyware Indicators",
        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
        "category": "malware",
        "format": "domains",
        "scale": "~1.5k domains",
        "description": "Blocks command-and-control servers used by mobile stalkerware, spyware, and covert surveillance apps.",
        "packs": ["malware"],
    },
    {
        "id": "stevenblack_fakenews",
        "name": "StevenBlack Clickbait & Disinformation Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
        "category": "custom",
        "format": "domains",
        "scale": "~3k domains",
        "description": "Filters known clickbait farms, deceptive tabloid networks, and automated content-mill domains.",
        "packs": [],
    },
]


def atomic_write(path: Path, payload: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = payload.encode() if isinstance(payload, str) else payload
    tmp = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def password_hash(password: str, salt: bytes | None = None) -> str:
    if not isinstance(password, str) or len(password) < 10 or len(password) > 200:
        raise ValueError("Password must contain between 10 and 200 characters")
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000, dklen=32)
    return base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def password_verify(password: str, encoded: str) -> bool:
    try:
        salt_text, digest_text = encoded.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000, dklen=32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.queue_lock = threading.Lock()
        self._pending_queries: collections.deque[tuple[float, str, str, int, str, str, float, int, str]] = collections.deque(maxlen=5000)
        self.db = sqlite3.connect(self.root / "lattice.db", timeout=30.0, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._schema()

        key_path = self.root / "secret.key"
        if not key_path.exists():
            atomic_write(key_path, Fernet.generate_key())
        self.cipher = Fernet(key_path.read_bytes())

        self.config = validate_config(self.meta("config", DEFAULT_CONFIG))
        self.sessions: dict[str, dict[str, Any]] = {}
        self.auth_failures: dict[str, list[float]] = {}
        self.pause_until: float = 0.0
        raw_modes = self.meta("device_modes", {})
        self.device_modes: dict[str, dict[str, Any]] = raw_modes if isinstance(raw_modes, dict) else {}
        self.setup_code = None if self.has_user() else secrets.token_urlsafe(24)
        self.event_cond = threading.Condition()
        self._live_events: collections.deque[dict[str, Any]] = collections.deque(maxlen=200)
        self._event_seq: int = 0
        self.schedule: dict[str, Any] = self._load_schedule_from_meta()

    def _schema(self) -> None:
        with self.lock, self.db:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS secrets(
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    password_hash TEXT NOT NULL,
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rules(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    action TEXT NOT NULL,
                    value TEXT NOT NULL DEFAULT '',
                    profile TEXT NOT NULL DEFAULT '*',
                    expires REAL,
                    created REAL NOT NULL,
                    UNIQUE(pattern, kind, profile)
                );
                CREATE TABLE IF NOT EXISTS feeds(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    category TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    format TEXT NOT NULL DEFAULT 'auto',
                    refreshed REAL NOT NULL DEFAULT 0,
                    domain_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS feed_domains(
                    feed_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    PRIMARY KEY(feed_id, domain),
                    FOREIGN KEY(feed_id) REFERENCES feeds(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS feed_domains_lookup ON feed_domains(domain, category);
                CREATE TABLE IF NOT EXISTS queries(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    client TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    qtype INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    latency REAL NOT NULL,
                    rcode INTEGER NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS queries_ts ON queries(ts DESC);
                CREATE INDEX IF NOT EXISTS queries_domain ON queries(domain, ts DESC);
                CREATE INDEX IF NOT EXISTS queries_ts_action ON queries(ts DESC, action);
                CREATE INDEX IF NOT EXISTS queries_client_ts ON queries(client, ts DESC);
                CREATE TABLE IF NOT EXISTS devices(
                    ip TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    icon TEXT NOT NULL DEFAULT 'device',
                    profile TEXT NOT NULL DEFAULT '*',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    query_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS devices_last_seen ON devices(last_seen DESC);
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts DESC);
                CREATE TABLE IF NOT EXISTS upstream_health(
                    upstream TEXT PRIMARY KEY,
                    checked REAL NOT NULL,
                    healthy INTEGER NOT NULL,
                    latency REAL,
                    error TEXT NOT NULL DEFAULT ''
                );
                """
            )

    def _flush_pending_queries_locked(self) -> None:
        with self.queue_lock:
            if not self._pending_queries:
                return
            batch = list(self._pending_queries)
            self._pending_queries.clear()
        privacy = self.config["privacy"]["mode"]
        with self.db:
            self.db.executemany(
                "INSERT INTO queries(ts,client,domain,qtype,action,profile,latency,rcode,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                batch,
            )
            if privacy != "strict":
                dev_agg: dict[str, list[ Any ]] = {}
                for row in batch:
                    ts_val, client_val = row[0], row[1]
                    if client_val not in dev_agg:
                        dev_agg[client_val] = [ts_val, ts_val, 1]
                    else:
                        item = dev_agg[client_val]
                        if ts_val > item[1]:
                            item[1] = ts_val
                        item[2] += 1
                self.db.executemany(
                    """
                    INSERT INTO devices(ip, first_seen, last_seen, query_count)
                    VALUES(?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        query_count = devices.query_count + excluded.query_count
                    """,
                    [(ip, vals[0], vals[1], vals[2]) for ip, vals in dev_agg.items()],
                )

    def meta(self, key: str, default: Any = None) -> Any:
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set_meta(self, key: str, value: Any) -> None:
        encoded = json.dumps(value, separators=(",", ":"))
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, encoded),
            )

    def set_config(self, raw: dict[str, Any]) -> dict[str, Any]:
        validated = validate_config(raw)
        self.set_meta("config", validated)
        self.config = validated
        return validated

    def secret(self, key: str) -> str:
        with self.lock:
            row = self.db.execute("SELECT value FROM secrets WHERE key=?", (key,)).fetchone()
        if not row:
            return ""
        try:
            return self.cipher.decrypt(row["value"]).decode()
        except Exception:
            return ""

    def set_secret(self, key: str, value: str) -> None:
        if key not in {"cloudflare", "frp"}:
            raise ValueError("Unknown secret")
        if value == "":
            with self.lock, self.db:
                self.db.execute("DELETE FROM secrets WHERE key=?", (key,))
            return
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError("Secret is invalid")
        encrypted = self.cipher.encrypt(value.encode())
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO secrets(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, encrypted),
            )

    def has_user(self) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM users WHERE id=1").fetchone() is not None

    def check_auth_rate_limit(self, client_ip: str) -> None:
        now = time.time()
        with self.queue_lock:
            attempts = [t for t in self.auth_failures.get(client_ip, []) if now - t < 60.0]
            self.auth_failures[client_ip] = attempts
            if len(attempts) >= 12:
                raise PermissionError("Too many failed authentication attempts; try again in 60 seconds")

    def record_auth_failure(self, client_ip: str) -> None:
        now = time.time()
        with self.queue_lock:
            attempts = [t for t in self.auth_failures.get(client_ip, []) if now - t < 60.0]
            attempts.append(now)
            self.auth_failures[client_ip] = attempts

    def complete_setup(self, code: str, password: str) -> None:
        if self.has_user():
            raise ValueError("Setup has already been completed")
        if not self.setup_code or not secrets.compare_digest(code, self.setup_code):
            raise ValueError("Setup code is invalid")
        encoded = password_hash(password)
        with self.lock, self.db:
            self.db.execute("INSERT INTO users(id,password_hash,created) VALUES(1,?,?)", (encoded, time.time()))
        self.setup_code = None
        self.audit("Administrator account created")

    def authenticate(self, password: str) -> str:
        with self.lock:
            row = self.db.execute("SELECT password_hash FROM users WHERE id=1").fetchone()
        if not row or not password_verify(password, row["password_hash"]):
            raise ValueError("Invalid password")
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {
            "expires": time.time() + 86400,
            "csrf": secrets.token_urlsafe(24),
        }
        return token

    def session(self, token: str) -> dict[str, Any] | None:
        item = self.sessions.get(token)
        if not item:
            return None
        if item["expires"] < time.time():
            self.sessions.pop(token, None)
            return None
        return item

    def logout(self, token: str) -> None:
        self.sessions.pop(token, None)

    def audit(self, event: str, detail: str = "") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit(ts,event,detail) VALUES(?,?,?)", (time.time(), event[:160], detail[:1000]))

    def rows(self, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.lock:
            self._flush_pending_queries_locked()
            return [dict(row) for row in self.db.execute(sql, args).fetchall()]

    def rule_rows(self) -> list[dict[str, Any]]:
        now = time.time()
        with self.lock, self.db:
            self.db.execute("DELETE FROM rules WHERE expires IS NOT NULL AND expires<=?", (now,))
            return [dict(row) for row in self.db.execute("SELECT * FROM rules ORDER BY id DESC")]

    def add_rule(self, pattern: str, kind: str, action: str, value: str, profile: str, expires: float | None) -> dict[str, Any]:
        if kind not in ("exact", "suffix", "regex") or action not in ("allow", "deny", "rewrite"):
            raise ValueError("Invalid rule kind or action")
        if kind == "regex":
            if len(pattern) > 200:
                raise ValueError("Regex pattern is too long")
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Invalid regular expression: {exc}") from exc
        if expires is not None and (not isinstance(expires, (int, float)) or expires <= time.time()):
            raise ValueError("Rule expiry must be in the future")
        with self.lock, self.db:
            self.db.execute(
                """
                INSERT INTO rules(pattern,kind,action,value,profile,expires,created)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(pattern,kind,profile) DO UPDATE SET
                    action=excluded.action,
                    value=excluded.value,
                    expires=excluded.expires
                """,
                (pattern, kind, action, value, profile, expires, time.time()),
            )
            row = self.db.execute(
                "SELECT * FROM rules WHERE pattern=? AND kind=? AND profile=?",
                (pattern, kind, profile),
            ).fetchone()
        self.audit("Rule saved", f"{action} {pattern}")
        return dict(row)

    def delete_rule(self, rule_id: int) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        self.audit("Rule deleted", str(rule_id))

    def log_query(
        self,
        client: str,
        domain: str,
        qtype: int,
        action: str,
        profile: str,
        latency: float,
        rcode: int,
        detail: str = "",
    ) -> None:
        privacy = self.config["privacy"]["mode"]
        profile_cfg = next((p for p in self.config["profiles"] if p["id"] == profile), None)
        if privacy == "minimal" or not profile_cfg or not profile_cfg["logging"]:
            return
        if privacy == "balanced":
            client = hashlib.sha256(client.encode()).hexdigest()[:16]
        now = time.time()
        entry = (now, client, domain, qtype, action, profile, round(latency, 3), rcode, detail[:500])
        with self.event_cond:
            self._event_seq += 1
            self._live_events.append({
                "id": self._event_seq,
                "seq": self._event_seq,
                "ts": now,
                "client": client,
                "domain": domain,
                "qtype": qtype,
                "action": action,
                "profile": profile,
                "latency": round(latency, 2),
                "rcode": rcode,
                "detail": detail[:500],
            })
            self.event_cond.notify_all()

        with self.queue_lock:
            self._pending_queries.append(entry)
            should_flush = len(self._pending_queries) >= 32
        if not should_flush or not self.lock.acquire(blocking=False):
            return
        try:
            self._flush_pending_queries_locked()
        finally:
            self.lock.release()

    def clear_queries(self) -> int:
        with self.lock, self.db:
            with self.queue_lock:
                self._pending_queries.clear()
            cur = self.db.execute("DELETE FROM queries")
            count = cur.rowcount
        self.audit("Query log cleared", f"Removed {count} entries")
        return count

    def cleanup(self) -> None:
        cutoff = time.time() - self.config["privacy"]["retention_days"] * 86400
        cutoff_audit = time.time() - 90 * 86400
        with self.lock, self.db:
            self._flush_pending_queries_locked()
            self.db.execute("DELETE FROM queries WHERE ts<?", (cutoff,))
            self.db.execute("DELETE FROM audit WHERE ts<?", (cutoff_audit,))
        now = time.time()
        for token, session in list(self.sessions.items()):
            if session["expires"] < now:
                self.sessions.pop(token, None)

    def dashboard(self, window: int = 86400) -> dict[str, Any]:
        window = max(300, int(window))
        cutoff = time.time() - window
        if window <= 3600:
            bucket_sec = 60
        elif window <= 21600:
            bucket_sec = 300
        elif window <= 86400:
            bucket_sec = 900
        else:
            bucket_sec = 3600

        with self.lock:
            self._flush_pending_queries_locked()
            summary = self.db.execute(
                """
                SELECT count(*) total,
                       sum(action='blocked') blocked,
                       sum(action='allowed') allowed,
                       sum(action='rewritten') rewritten,
                       sum(action='error') errors,
                       avg(latency) latency
                FROM queries WHERE ts>=?
                """,
                (cutoff,),
            ).fetchone()
            top = self.db.execute(
                "SELECT domain,count(*) count FROM queries WHERE ts>=? AND domain<>'' GROUP BY domain ORDER BY count DESC LIMIT 8",
                (cutoff,),
            ).fetchall()
            top_blocked = self.db.execute(
                "SELECT domain,count(*) count FROM queries WHERE ts>=? AND action='blocked' AND domain<>'' GROUP BY domain ORDER BY count DESC LIMIT 8",
                (cutoff,),
            ).fetchall()
            top_allowed = self.db.execute(
                "SELECT domain,count(*) count FROM queries WHERE ts>=? AND action='allowed' AND domain<>'' GROUP BY domain ORDER BY count DESC LIMIT 8",
                (cutoff,),
            ).fetchall()
            top_clients = self.db.execute(
                """
                SELECT q.client, count(*) count, sum(q.action='blocked') blocked,
                       COALESCE(d.name, '') name, COALESCE(d.icon, 'device') icon
                FROM queries q
                LEFT JOIN devices d ON d.ip = q.client
                WHERE q.ts>=? AND q.client<>''
                GROUP BY q.client ORDER BY count DESC LIMIT 8
                """,
                (cutoff,),
            ).fetchall()
            qtypes = self.db.execute(
                "SELECT qtype,count(*) count FROM queries WHERE ts>=? GROUP BY qtype ORDER BY count DESC",
                (cutoff,),
            ).fetchall()
            actions = self.db.execute(
                "SELECT action,count(*) count FROM queries WHERE ts>=? GROUP BY action",
                (cutoff,),
            ).fetchall()
            prof_rows = self.db.execute(
                """
                SELECT profile, count(*) total, COALESCE(sum(action='blocked'), 0) blocked, COALESCE(avg(latency), 0) latency
                FROM queries WHERE ts>=? GROUP BY profile ORDER BY total DESC
                """,
                (cutoff,),
            ).fetchall()
            lat_rows = [
                float(r["latency"])
                for r in self.db.execute(
                    "SELECT latency FROM queries WHERE ts>=? ORDER BY latency ASC LIMIT 5000",
                    (cutoff,),
                ).fetchall()
            ]
            cache_win_row = self.db.execute(
                "SELECT count(*) c FROM queries WHERE ts>=? AND (detail LIKE '%cache:%' OR detail='cached')",
                (cutoff,),
            ).fetchone()
            sec_win_row = self.db.execute(
                "SELECT count(*) c FROM queries WHERE ts>=? AND (detail LIKE 'security:%' OR detail LIKE 'cname_cloak:%' OR detail LIKE 'schedule:%')",
                (cutoff,),
            ).fetchone()
            recent_live_rows = self.db.execute(
                """
                SELECT q.id, q.ts, q.client, q.domain, q.qtype, q.action, q.profile, q.latency, q.rcode, q.detail,
                       COALESCE(d.name, '') device_name, COALESCE(d.icon, 'device') device_icon
                FROM queries q
                LEFT JOIN devices d ON d.ip = q.client
                ORDER BY q.id DESC LIMIT 8
                """
            ).fetchall()
            series = self.db.execute(
                f"""
                SELECT CAST(ts/{bucket_sec} AS INTEGER)*{bucket_sec} bucket,
                       count(*) total,
                       COALESCE(sum(action='blocked'), 0) blocked
                FROM queries WHERE ts>=?
                GROUP BY bucket ORDER BY bucket
                """,
                (cutoff,),
            ).fetchall()
        raw_series = {int(x["bucket"]): {"bucket": int(x["bucket"]), "total": int(x["total"] or 0), "blocked": int(x["blocked"] or 0)} for x in series}
        if raw_series and len(raw_series) < 12:
            now_bucket = int(time.time() // bucket_sec) * bucket_sec
            num_points = 12
            filled_series = []
            for i in range(num_points - 1, -1, -1):
                b_ts = now_bucket - i * bucket_sec
                filled_series.append(raw_series.get(b_ts, {"bucket": b_ts, "total": 0, "blocked": 0}))
            for k in sorted(raw_series.keys()):
                if all(item["bucket"] != k for item in filled_series):
                    filled_series.append(raw_series[k])
            filled_series.sort(key=lambda item: item["bucket"])
        else:
            filled_series = [raw_series[k] for k in sorted(raw_series.keys())]

        def _pct(sorted_vals: list[float], p: float) -> float:
            if not sorted_vals:
                return 0.0
            idx = min(len(sorted_vals) - 1, max(0, int(math.ceil((p / 100.0) * len(sorted_vals)) - 1)))
            return round(sorted_vals[idx], 2)

        return {
            "total": summary["total"] or 0,
            "blocked": summary["blocked"] or 0,
            "allowed": summary["allowed"] or 0,
            "rewritten": summary["rewritten"] or 0,
            "errors": summary["errors"] or 0,
            "latency": round(summary["latency"] or 0, 2),
            "p50_latency": _pct(lat_rows, 50),
            "p95_latency": _pct(lat_rows, 95),
            "p99_latency": _pct(lat_rows, 99),
            "cache_hits_window": int(cache_win_row["c"] or 0) if cache_win_row else 0,
            "security_blocks_window": int(sec_win_row["c"] or 0) if sec_win_row else 0,
            "recent_live": [dict(x) for x in recent_live_rows],
            "top_domains": [dict(x) for x in top],
            "top_blocked": [dict(x) for x in top_blocked],
            "top_allowed": [dict(x) for x in top_allowed],
            "top_clients": [dict(x) for x in top_clients],
            "qtypes": [dict(x) for x in qtypes],
            "actions": [dict(x) for x in actions],
            "profile_stats": [dict(x) for x in prof_rows],
            "series": filled_series,
        }

    def threat_snapshot(self) -> dict[str, Any]:
        cutoff = time.time() - 3600
        with self.lock:
            self._flush_pending_queries_locked()
            row = self.db.execute(
                """
                SELECT count(*) total,
                       sum(rcode=3) nxdomain,
                       count(DISTINCT domain) unique_domains
                FROM queries WHERE ts>=?
                """,
                (cutoff,),
            ).fetchone()
            burst = self.db.execute(
                """
                SELECT client,count(*) count,count(DISTINCT domain) unique_domains
                FROM queries WHERE ts>=?
                GROUP BY client ORDER BY count DESC LIMIT 5
                """,
                (cutoff,),
            ).fetchall()
            recent_domains = [
                x["domain"]
                for x in self.db.execute(
                    "SELECT DISTINCT domain FROM queries WHERE ts>=? AND domain<>'' LIMIT 100", (cutoff,)
                ).fetchall()
            ]
        total = row["total"] or 0
        nx = row["nxdomain"] or 0
        suspicious_dga = []
        for d in recent_domains:
            label = d.split(".")[0]
            if len(label) >= 11:
                ent = shannon_entropy(label)
                if ent >= 3.5:
                    suspicious_dga.append({"domain": d, "entropy": ent})
        return {
            "queries": total,
            "unique_domains": row["unique_domains"] or 0,
            "nxdomain_ratio": round(nx / total, 4) if total else 0,
            "clients": [dict(x) for x in burst],
            "dga_suspicious": suspicious_dga[:8],
        }

    def pause_blocking(self, seconds: int) -> dict[str, Any]:
        with self.lock:
            if seconds <= 0:
                self.pause_until = 0.0
                self.audit("Blocking resumed", "Manual resume from UI")
            else:
                self.pause_until = time.time() + seconds
                self.audit("Blocking paused", f"Paused for {seconds} seconds")
            return self.blocking_pause_status()

    def is_blocking_paused(self) -> bool:
        return time.time() < self.pause_until

    def blocking_pause_status(self) -> dict[str, Any]:
        now = time.time()
        remaining = max(0, int(self.pause_until - now))
        return {
            "paused": remaining > 0,
            "remaining": remaining,
            "until": self.pause_until if remaining > 0 else 0,
        }

    def get_device_mode(self, ip: str) -> str:
        clean_ip = ip.strip()
        if not clean_ip:
            return "normal"
        with self.queue_lock:
            entry = self.device_modes.get(clean_ip)
            if not entry:
                return "normal"
            exp = entry.get("expires")
            if exp is not None and float(exp) <= time.time():
                self.device_modes.pop(clean_ip, None)
                return "normal"
            return str(entry.get("mode", "normal"))

    def set_device_mode(self, ip: str, mode: str = "normal", seconds: int = 0) -> dict[str, Any]:
        import ipaddress
        clean_ip = str(ipaddress.ip_address(ip.strip()))
        if mode not in ("normal", "bypass", "quarantine"):
            raise ValueError("Device mode must be normal, bypass, or quarantine")
        expires = (time.time() + max(1, min(86400 * 7, int(seconds)))) if (seconds > 0 and mode != "normal") else None
        with self.queue_lock:
            if mode == "normal":
                self.device_modes.pop(clean_ip, None)
            else:
                self.device_modes[clean_ip] = {"mode": mode, "expires": expires}
            snapshot = copy.deepcopy(self.device_modes)
        self.set_meta("device_modes", snapshot)
        self.audit("Device mode updated", f"{clean_ip} -> {mode}" + (f" ({seconds}s)" if expires else ""))
        return {"ok": True, "ip": clean_ip, "mode": mode, "expires": expires}

    def get_devices(self) -> list[dict[str, Any]]:
        with self.lock:
            self._flush_pending_queries_locked()
            rows = self.rows("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 200")
        for r in rows:
            r["mode"] = self.get_device_mode(r["ip"])
        return rows

    def update_device(self, ip: str, name: str, icon: str = "device", profile: str = "*") -> None:
        now = time.time()
        with self.lock:
            self._flush_pending_queries_locked()
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO devices(ip, name, icon, profile, first_seen, last_seen, query_count)
                    VALUES(?, ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(ip) DO UPDATE SET
                        name = excluded.name,
                        icon = excluded.icon,
                        profile = excluded.profile
                    """,
                    (ip, name, icon, profile, now, now),
                )
        self.audit("Device updated", f"{ip}: {name} ({icon}, {profile})")

    def delete_device(self, ip: str) -> None:
        with self.lock:
            self._flush_pending_queries_locked()
            with self.db:
                self.db.execute("DELETE FROM devices WHERE ip=?", (ip,))
        self.audit("Device deleted", ip)

    def export_queries_csv(self, limit: int = 5000, action: str = "", q: str = "", qtype: int = 0) -> str:
        sql = "SELECT * FROM queries WHERE 1=1"
        args: list[Any] = []
        if q:
            sql += " AND (LOWER(domain) LIKE ? OR LOWER(client) LIKE ?)"
            args.extend([f"%{q.lower()}%", f"%{q.lower()}%"])
        if action and action != "all":
            sql += " AND action = ?"
            args.append(action)
        if qtype > 0:
            sql += " AND qtype = ?"
            args.append(qtype)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = self.rows(sql, tuple(args))

        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["Timestamp_ISO", "Unix_TS", "Client_IP", "Domain", "QType", "Action", "Profile", "Latency_MS", "RCode", "Detail"])
        for r in rows:
            iso_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"]))
            writer.writerow([
                iso_time,
                r["ts"],
                r["client"],
                r["domain"],
                r["qtype"],
                r["action"],
                r["profile"],
                r["latency"],
                r["rcode"],
                r["detail"],
            ])
        return out.getvalue()

    def import_rules(self, text: str, action: str = "deny", profile: str = "*", kind: str = "exact") -> dict[str, int]:
        lines = text.strip().splitlines()
        added = 0
        skipped = 0
        for line in lines:
            line = line.split("#", 1)[0].split("!", 1)[0].strip()
            if not line:
                continue
            rule_kind = kind
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
                raw = parts[1]
            elif line.startswith("||") and line.endswith("^"):
                raw = line[2:-1]
                rule_kind = "suffix"
            elif line.startswith("||"):
                raw = line[2:].split("^", 1)[0]
                rule_kind = "suffix"
            else:
                raw = line
            raw = raw.lstrip("*.").rstrip(".")
            try:
                domain = hostname(raw, "import pattern")
                self.add_rule(domain, rule_kind, action, "", profile, None)
                added += 1
            except Exception:
                skipped += 1
        return {"added": added, "skipped": skipped}

    def clear_expired_rules(self) -> int:
        now = time.time()
        with self.lock, self.db:
            cur = self.db.execute("DELETE FROM rules WHERE expires IS NOT NULL AND expires <= ?", (now,))
            count = cur.rowcount
        if count > 0:
            self.audit("Expired rules cleared", f"Removed {count} expired rules")
        return count

    def get_presets_status(self) -> list[dict[str, Any]]:
        active_deny_patterns = {r["pattern"] for r in self.rule_rows() if r["action"] == "deny"}
        result = []
        for key, p in PRESETS.items():
            blocked_count = sum(1 for d in p["domains"] if d in active_deny_patterns)
            result.append({
                "id": key,
                "name": p["name"],
                "group": p.get("group", "social"),
                "description": p["description"],
                "domains": p["domains"],
                "blocked": blocked_count == len(p["domains"]),
                "partial": 0 < blocked_count < len(p["domains"]),
            })
        return result

    def toggle_preset(self, preset_id: str, enable: bool) -> dict[str, Any]:
        preset = PRESETS.get(preset_id)
        if not preset:
            raise ValueError(f"Unknown preset: {preset_id}")
        with self.lock:
            for domain in preset["domains"]:
                if enable:
                    self.add_rule(domain, "suffix", "deny", "", "*", None)
                else:
                    with self.db:
                        self.db.execute("DELETE FROM rules WHERE pattern=? AND action='deny'", (domain,))
        self.audit("Preset updated", f"{preset['name']} ({'blocked' if enable else 'unblocked'})")
        return {"ok": True, "preset": preset_id, "enabled": enable}

    def feed_rows(self) -> list[dict[str, Any]]:
        return self.rows("SELECT * FROM feeds ORDER BY id")

    def feeds(self) -> list[dict[str, Any]]:
        return self.feed_rows()

    def install_recommended_bundle(self) -> dict[str, Any]:
        existing_urls = {r["url"] for r in self.feed_rows()}
        added = 0
        with self.lock, self.db:
            for item in RECOMMENDED_FEED_BUNDLE:
                if item["url"] not in existing_urls:
                    self.db.execute(
                        "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,1)",
                        (item["name"], item["url"], item["category"], item["format"]),
                    )
                    added += 1
        return {"ok": True, "added": added, "installed": added, "total_bundle": len(RECOMMENDED_FEED_BUNDLE), "feeds": self.feed_rows()}

    def _load_schedule_from_meta(self) -> dict[str, Any]:
        raw = self.meta("focus_schedule", None)
        merged = copy.deepcopy(DEFAULT_SCHEDULE)
        if isinstance(raw, dict):
            for k in merged:
                if k in raw:
                    merged[k] = raw[k]
        merged["start_time"] = merged["start"]
        merged["end_time"] = merged["end"]
        return merged

    def get_schedule(self) -> dict[str, Any]:
        return copy.deepcopy(self.schedule)

    def set_schedule(self, payload: dict[str, Any]) -> dict[str, Any]:
        current = self.get_schedule()
        if not isinstance(payload, dict):
            raise ValueError("Schedule payload must be an object")
        if "enabled" in payload:
            current["enabled"] = bool(payload["enabled"])
        if "mode" in payload and str(payload["mode"]) in ("bedtime", "focus", "kids", "custom"):
            current["mode"] = str(payload["mode"])
        for t_field, alias in (("start", "start_time"), ("end", "end_time")):
            raw_time = payload.get(t_field) if t_field in payload else payload.get(alias)
            if raw_time is not None:
                val = str(raw_time).strip()
                parts = val.split(":")
                if len(parts) != 2 or not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59):
                    raise ValueError(f"Invalid schedule {t_field} time (expected HH:MM)")
                current[t_field] = f"{int(parts[0]):02d}:{int(parts[1]):02d}"
        if "days" in payload and isinstance(payload["days"], list):
            valid_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
            day_index_map = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}
            parsed_days: list[str] = []
            for d in payload["days"]:
                if isinstance(d, int) and d in day_index_map:
                    parsed_days.append(day_index_map[d])
                else:
                    s = str(d).lower()[:3]
                    if s in valid_days:
                        parsed_days.append(s)
            current["days"] = parsed_days
        if "presets" in payload and isinstance(payload["presets"], list):
            current["presets"] = [str(p) for p in payload["presets"] if str(p) in PRESETS]
        if "categories" in payload and isinstance(payload["categories"], list):
            current["categories"] = [str(c).strip().lower() for c in payload["categories"] if str(c).strip()]
        if "profile" in payload:
            current["profile"] = str(payload["profile"] or "*")
        current["start_time"] = current["start"]
        current["end_time"] = current["end"]
        self.schedule = copy.deepcopy(current)
        self.set_meta("focus_schedule", current)
        self.audit("Schedule updated", f"enabled={current['enabled']} ({current['start']}-{current['end']}) profile={current['profile']}")
        return current

    def is_schedule_active(self, now_ts: float | None = None, profile: str = "*") -> tuple[bool, dict[str, Any]]:
        sched = self.schedule
        if not sched.get("enabled"):
            return False, sched
        target_prof = sched.get("profile", "*") or "*"
        if profile != "*" and target_prof not in ("*", profile):
            return False, sched
        tm = time.localtime(now_ts if now_ts is not None else time.time())
        day_name = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")[tm.tm_wday]
        if day_name not in sched.get("days", []):
            return False, sched
        try:
            sh, sm = (int(x) for x in sched["start"].split(":"))
            eh, em = (int(x) for x in sched["end"].split(":"))
        except Exception:
            return False, sched
        start_min = sh * 60 + sm
        end_min = eh * 60 + em
        cur_min = tm.tm_hour * 60 + tm.tm_min
        if start_min <= end_min:
            active = start_min <= cur_min <= end_min
        else:
            active = cur_min >= start_min or cur_min <= end_min
        return active, sched

    def get_events_since(self, since_seq: int = 0, limit: int = 50) -> dict[str, Any]:
        with self.event_cond:
            items = [e for e in self._live_events if e["seq"] > since_seq]
            return {"seq": self._event_seq, "events": items[-limit:]}

    def wait_for_events(self, since_seq: int = 0, timeout: float = 10.0) -> dict[str, Any]:
        with self.event_cond:
            if self._event_seq <= since_seq:
                self.event_cond.wait(timeout=max(0.1, min(20.0, timeout)))
            items = [e for e in self._live_events if e["seq"] > since_seq]
            return {"seq": self._event_seq, "events": items[-50:]}

    def get_catalog_status(self) -> list[dict[str, Any]]:
        installed_by_url = {f["url"]: f for f in self.feed_rows()}
        out: list[dict[str, Any]] = []
        for item in CURATED_BLOCKLIST_CATALOG:
            inst = installed_by_url.get(item["url"])
            out.append({
                **item,
                "installed": inst is not None,
                "feed_id": inst["id"] if inst else None,
                "enabled": bool(inst["enabled"]) if inst else False,
                "domain_count": int(inst["domain_count"] or 0) if inst else 0,
            })
        return out

    def install_catalog_items(self, feed_id: str = "", pack: str = "") -> dict[str, Any]:
        existing = {f["url"]: f for f in self.feed_rows()}
        targets: list[dict[str, Any]] = []
        if pack:
            targets = [item for item in CURATED_BLOCKLIST_CATALOG if pack in item.get("packs", [])]
        elif feed_id:
            targets = [item for item in CURATED_BLOCKLIST_CATALOG if item["id"] == feed_id]
        else:
            targets = [item for item in CURATED_BLOCKLIST_CATALOG if "core" in item.get("packs", [])]

        added = 0
        with self.lock, self.db:
            for item in targets:
                if item["url"] not in existing:
                    self.db.execute(
                        "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,1,?)",
                        (item["name"], item["url"], item["category"], item["format"]),
                    )
                    added += 1
        self.audit("Blocklist catalog installed", f"pack={pack or feed_id or 'core'} added={added}")
        return {
            "ok": True,
            "added": added,
            "installed": added,
            "target_count": len(targets),
            "catalog": self.get_catalog_status(),
            "feeds": self.feed_rows(),
        }

    def search_blocklists(self, q: str, limit: int = 30) -> dict[str, Any]:
        clean = q.strip().lower().rstrip(".")
        if not clean:
            return {"query": "", "feed_matches": [], "rule_matches": [], "preset_matches": [], "catalog_matches": []}
        like_pat = f"%{clean}%"
        with self.lock:
            feed_matches = [
                dict(r)
                for r in self.db.execute(
                    """
                    SELECT fd.domain, fd.category, f.id feed_id, f.name feed_name, f.enabled
                    FROM feed_domains fd
                    JOIN feeds f ON f.id = fd.feed_id
                    WHERE fd.domain LIKE ?
                    ORDER BY LENGTH(fd.domain) ASC
                    LIMIT ?
                    """,
                    (like_pat, limit),
                ).fetchall()
            ]
            rule_matches = [
                dict(r)
                for r in self.db.execute(
                    "SELECT id, pattern, kind, action, profile, value FROM rules WHERE LOWER(pattern) LIKE ? ORDER BY id DESC LIMIT 20",
                    (like_pat,),
                ).fetchall()
            ]
        preset_matches = []
        for pid, p in PRESETS.items():
            matched_doms = [d for d in p["domains"] if clean in d or d in clean]
            if clean in pid or clean in p["name"].lower() or matched_doms:
                preset_matches.append({
                    "id": pid,
                    "name": p["name"],
                    "group": p.get("group", "social"),
                    "matched_domains": matched_doms or p["domains"][:3],
                })
        catalog_matches = [
            {"id": c["id"], "name": c["name"], "category": c["category"], "scale": c["scale"], "url": c["url"]}
            for c in CURATED_BLOCKLIST_CATALOG
            if clean in c["name"].lower() or clean in c["description"].lower() or clean in c["category"].lower()
        ]
        return {
            "query": clean,
            "feed_matches": feed_matches,
            "rule_matches": rule_matches,
            "preset_matches": preset_matches,
            "catalog_matches": catalog_matches,
        }

    def device_insights(self, ip: str, window: int = 86400) -> dict[str, Any]:
        clean_ip = ip.strip()
        cutoff = time.time() - max(300, int(window))
        with self.lock:
            self._flush_pending_queries_locked()
            dev_row = self.db.execute("SELECT * FROM devices WHERE ip=?", (clean_ip,)).fetchone()
            summary = self.db.execute(
                """
                SELECT count(*) total,
                       COALESCE(sum(action='blocked'), 0) blocked,
                       COALESCE(sum(action='allowed'), 0) allowed,
                       COALESCE(sum(action='rewritten'), 0) rewritten,
                       COALESCE(avg(latency), 0) avg_latency
                FROM queries WHERE client=? AND ts>=?
                """,
                (clean_ip, cutoff),
            ).fetchone()
            top_allowed = [
                dict(r)
                for r in self.db.execute(
                    "SELECT domain, count(*) count FROM queries WHERE client=? AND ts>=? AND action='allowed' AND domain<>'' GROUP BY domain ORDER BY count DESC LIMIT 6",
                    (clean_ip, cutoff),
                ).fetchall()
            ]
            top_blocked = [
                dict(r)
                for r in self.db.execute(
                    "SELECT domain, count(*) count FROM queries WHERE client=? AND ts>=? AND action='blocked' AND domain<>'' GROUP BY domain ORDER BY count DESC LIMIT 6",
                    (clean_ip, cutoff),
                ).fetchall()
            ]
            recent = [
                dict(r)
                for r in self.db.execute(
                    "SELECT id, ts, domain, qtype, action, profile, latency, rcode, detail FROM queries WHERE client=? ORDER BY id DESC LIMIT 10",
                    (clean_ip,),
                ).fetchall()
            ]
        total = int(summary["total"] or 0) if summary else 0
        blocked = int(summary["blocked"] or 0) if summary else 0
        return {
            "ip": clean_ip,
            "mode": self.get_device_mode(clean_ip),
            "name": dev_row["name"] if dev_row else "",
            "icon": dev_row["icon"] if dev_row else "device",
            "profile": dev_row["profile"] if dev_row else "*",
            "total": total,
            "blocked": blocked,
            "allowed": int(summary["allowed"] or 0) if summary else 0,
            "rewritten": int(summary["rewritten"] or 0) if summary else 0,
            "block_rate_pct": round((blocked / total) * 100, 1) if total else 0.0,
            "avg_latency": round(float(summary["avg_latency"] or 0.0), 2) if summary else 0.0,
            "top_allowed": top_allowed,
            "top_blocked": top_blocked,
            "recent": recent,
        }

    def system_overview(self) -> dict[str, Any]:
        db_bytes = 0
        for name in ("lattice.db", "lattice.db-wal", "lattice.db-shm"):
            p = self.root / name
            if p.exists():
                try:
                    db_bytes += p.stat().st_size
                except OSError:
                    pass
        with self.lock:
            self._flush_pending_queries_locked()
            q_cnt = int(self.db.execute("SELECT count(*) c FROM queries").fetchone()["c"] or 0)
            a_cnt = int(self.db.execute("SELECT count(*) c FROM audit").fetchone()["c"] or 0)
            fd_cnt = int(self.db.execute("SELECT count(*) c FROM feed_domains").fetchone()["c"] or 0)
            r_cnt = int(self.db.execute("SELECT count(*) c FROM rules").fetchone()["c"] or 0)
            d_cnt = int(self.db.execute("SELECT count(*) c FROM devices").fetchone()["c"] or 0)
        return {
            "db_size_bytes": db_bytes,
            "db_size_kb": round(db_bytes / 1024.0, 1),
            "db_size_mb": round(db_bytes / (1024.0 * 1024.0), 2),
            "total_queries_stored": q_cnt,
            "total_audit_rows": a_cnt,
            "total_feed_domains": fd_cnt,
            "total_rules": r_cnt,
            "total_devices": d_cnt,
            "active_sessions": len(self.sessions),
        }

    def vacuum_database(self) -> dict[str, Any]:
        before = self.system_overview()["db_size_bytes"]
        self.cleanup()
        self.clear_expired_rules()
        with self.lock:
            try:
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.db.execute("PRAGMA optimize")
            except Exception:
                pass
        after = self.system_overview()["db_size_bytes"]
        self.audit("Database optimized & checkpointed", f"before={before}B after={after}B")
        return {"ok": True, "before_bytes": before, "after_bytes": after, "system_info": self.system_overview()}

    def test_rule_pattern(self, pattern: str, kind: str = "suffix", sample: str = "") -> dict[str, Any]:
        clean_pat = pattern.strip()
        if not clean_pat:
            raise ValueError("Pattern is required")
        if kind not in ("exact", "suffix", "regex"):
            raise ValueError("Invalid match kind")

        def matches_domain(dom: str) -> bool:
            d = dom.strip().lower().rstrip(".")
            if not d:
                return False
            if kind == "exact":
                return d == clean_pat.lower().rstrip(".")
            if kind == "suffix":
                sfx = clean_pat.lower().lstrip("*.").rstrip(".")
                return d == sfx or d.endswith("." + sfx)
            try:
                return bool(re.search(clean_pat, d, re.IGNORECASE))
            except re.error as exc:
                raise ValueError(f"Invalid regular expression: {exc}") from exc

        sample_clean = sample.strip().lower().rstrip(".")
        sample_match = matches_domain(sample_clean) if sample_clean else None

        with self.lock:
            self._flush_pending_queries_locked()
            recent_domains = [
                r["domain"]
                for r in self.db.execute("SELECT DISTINCT domain FROM queries WHERE domain<>'' ORDER BY id DESC LIMIT 300").fetchall()
            ]
        matched_history = [d for d in recent_domains if matches_domain(d)][:15]
        return {
            "ok": True,
            "pattern": clean_pat,
            "kind": kind,
            "sample": sample_clean,
            "sample_matches": sample_match,
            "matched_recent_domains": matched_history,
            "matched_count": len(matched_history),
        }

    def close(self) -> None:
        with self.lock:
            try:
                self._flush_pending_queries_locked()
                self.db.close()
            except Exception:
                pass
