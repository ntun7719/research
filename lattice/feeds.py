"""Safe subscription download, gzip streaming, parallel sync, and atomic activation."""
from __future__ import annotations

import concurrent.futures
import gzip
import ipaddress
import socket
import time
import urllib.parse
import urllib.request
import zlib
from typing import Any

from .policy import parse_feed_line

MAX_BYTES = 64 * 1024 * 1024
MAX_DOMAINS = 3_000_000


def validate_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Feed URL is invalid")
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Feed URL must be a public HTTPS URL without credentials or fragments")
    if parsed.port not in (None, 443):
        raise ValueError("Feed URL must use HTTPS port 443")
    try:
        answers = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Feed hostname cannot be resolved") from exc
    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0])
        if not ip.is_global:
            raise ValueError("Feed URL must resolve only to public addresses")
    return urllib.parse.urlunsplit(parsed)


class FeedManager:
    def __init__(self, store, policy):
        self.store = store
        self.policy = policy

    def list(self) -> list[dict[str, Any]]:
        return self.store.rows("SELECT * FROM feeds ORDER BY id DESC")

    def add(self, name: str, url: str, category: str, mode: str = "auto", enabled: bool = True) -> dict[str, Any]:
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
            raise ValueError("Feed name must contain 1 to 100 characters")
        url = validate_url(url)
        if mode not in ("auto", "domains", "adblock"):
            raise ValueError("Feed format must be auto, domains or adblock")
        if not isinstance(category, str) or not category or len(category) > 40:
            raise ValueError("Feed category is invalid")
        category = category.strip().lower()
        if not all(ch.isalnum() or ch in "_-" for ch in category):
            raise ValueError("Feed category may contain lowercase letters, numbers, underscore and dash")
        with self.store.lock, self.store.db:
            cur = self.store.db.execute(
                "INSERT INTO feeds(name,url,category,enabled,format) VALUES(?,?,?,?,?)",
                (name.strip(), url, category, 1 if enabled else 0, mode),
            )
            row = self.store.db.execute("SELECT * FROM feeds WHERE id=?", (cur.lastrowid,)).fetchone()
        self.store.audit("Subscription created", name.strip())
        return dict(row)

    def delete(self, feed_id: int) -> None:
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM feeds WHERE id=?", (feed_id,))
        self.policy.compile()
        self.store.audit("Subscription deleted", str(feed_id))

    def set_enabled(self, feed_id: int, enabled: bool) -> None:
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE feeds SET enabled=? WHERE id=?", (1 if enabled else 0, feed_id))
        self.policy.compile()
        self.store.audit("Subscription toggled", f"{feed_id}:{enabled}")

    def _download(self, url: str) -> list[str]:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "LatticeDNS/12.0 (+https://github.com/ntun7719/research)",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        buf = bytearray()
        content_encoding = ""
        with urllib.request.urlopen(request, timeout=45) as response:
            final_url = response.geturl()
            if final_url != url:
                validate_url(final_url)
            if hasattr(response, "headers") and response.headers:
                content_encoding = str(response.headers.get("Content-Encoding", "")).lower().strip()
            while True:
                chunk = response.read(512 * 1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > MAX_BYTES:
                    raise ValueError("Feed exceeds the 64 MiB safety limit")
        raw_bytes = bytes(buf)
        if not raw_bytes:
            return []
        if content_encoding == "gzip" or raw_bytes[:2] == b"\x1f\x8b":
            raw_bytes = gzip.decompress(raw_bytes)
            if len(raw_bytes) > MAX_BYTES * 2:
                raise ValueError("Decompressed feed exceeds safety limit")
        elif content_encoding == "deflate":
            try:
                raw_bytes = zlib.decompress(raw_bytes)
            except zlib.error:
                raw_bytes = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
        text = raw_bytes.decode("utf-8", "replace")
        return text.splitlines()

    def _parse_lines(self, lines: list[str], fmt: str) -> set[str]:
        parsed: set[str] = set()
        for line in lines:
            domain = parse_feed_line(line, fmt)
            if domain:
                parsed.add(domain)
                if len(parsed) > MAX_DOMAINS:
                    raise ValueError("Feed exceeds the 3 million domain safety limit")
        if not parsed:
            raise ValueError("Feed produced no valid domains")
        return parsed

    def _commit_parsed(self, feed: dict[str, Any], parsed: set[str]) -> None:
        feed_id = feed["id"]
        with self.store.lock, self.store.db:
            self.store.db.execute("CREATE TEMP TABLE IF NOT EXISTS stage_feed(domain TEXT PRIMARY KEY)")
            self.store.db.execute("DELETE FROM stage_feed")
            self.store.db.executemany("INSERT OR IGNORE INTO stage_feed(domain) VALUES(?)", ((d,) for d in parsed))
            self.store.db.execute("DELETE FROM feed_domains WHERE feed_id=?", (feed_id,))
            self.store.db.execute(
                "INSERT INTO feed_domains(feed_id,category,domain) SELECT ?,?,domain FROM stage_feed",
                (feed_id, feed["category"]),
            )
            self.store.db.execute(
                "UPDATE feeds SET refreshed=?,domain_count=?,error='' WHERE id=?",
                (time.time(), len(parsed), feed_id),
            )

    def refresh_one(self, feed_id: int, recompile: bool = True) -> dict[str, Any]:
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM feeds WHERE id=?", (feed_id,)).fetchone()
        if not row:
            raise ValueError("Subscription does not exist")
        feed = dict(row)
        if not feed["enabled"]:
            return feed
        try:
            url = validate_url(feed["url"])
            lines = self._download(url)
            parsed = self._parse_lines(lines, feed["format"])
            self._commit_parsed(feed, parsed)
            if recompile:
                self.policy.compile()
            self.store.audit("Subscription refreshed", f"{feed['name']}:{len(parsed)}")
        except Exception as exc:
            with self.store.lock, self.store.db:
                self.store.db.execute("UPDATE feeds SET error=? WHERE id=?", (str(exc)[:500], feed_id))
            raise
        with self.store.lock:
            refreshed = self.store.db.execute("SELECT * FROM feeds WHERE id=?", (feed_id,)).fetchone()
        return dict(refreshed)

    def refresh_all(self) -> list[dict[str, Any]]:
        enabled_feeds = [f for f in self.list() if f["enabled"]]
        if not enabled_feeds:
            return []

        def fetch_and_parse(feed: dict[str, Any]) -> tuple[dict[str, Any], set[str] | None, str]:
            try:
                url = validate_url(feed["url"])
                lines = self._download(url)
                parsed = self._parse_lines(lines, feed["format"])
                return feed, parsed, ""
            except Exception as exc:
                return feed, None, str(exc)

        output: list[dict[str, Any]] = []
        any_updated = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(enabled_feeds))) as pool:
            for feed, parsed, err in pool.map(fetch_and_parse, enabled_feeds):
                if parsed is not None:
                    try:
                        self._commit_parsed(feed, parsed)
                        any_updated = True
                        self.store.audit("Subscription refreshed", f"{feed['name']}:{len(parsed)}")
                        with self.store.lock:
                            refreshed = self.store.db.execute("SELECT * FROM feeds WHERE id=?", (feed["id"],)).fetchone()
                        output.append(dict(refreshed))
                    except Exception as exc:
                        output.append({"id": feed["id"], "name": feed["name"], "error": str(exc)})
                else:
                    with self.store.lock, self.store.db:
                        self.store.db.execute("UPDATE feeds SET error=? WHERE id=?", (err[:500], feed["id"]))
                    output.append({"id": feed["id"], "name": feed["name"], "error": err})

        if any_updated:
            self.policy.compile()
        return output
