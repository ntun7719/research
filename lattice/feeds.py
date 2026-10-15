"""Safe subscription download, parsing and atomic activation."""
from __future__ import annotations

import ipaddress
import socket
import time
import urllib.parse
import urllib.request
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
        request = urllib.request.Request(url, headers={"User-Agent": "LatticeDNS/0.1"})
        domains: set[str] = set()
        total = 0
        with urllib.request.urlopen(request, timeout=45) as response:
            final_url = response.geturl()
            if final_url != url:
                validate_url(final_url)
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError("Feed exceeds the 64 MiB safety limit")
                if total == len(chunk):
                    buffer = chunk
                else:
                    buffer += chunk
        text = buffer.decode("utf-8", "replace") if total else ""
        return text.splitlines()

    def refresh_one(self, feed_id: int) -> dict[str, Any]:
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
            parsed: set[str] = set()
            for line in lines:
                domain = parse_feed_line(line, feed["format"])
                if domain:
                    parsed.add(domain)
                    if len(parsed) > MAX_DOMAINS:
                        raise ValueError("Feed exceeds the 3 million domain safety limit")
            if not parsed:
                raise ValueError("Feed produced no valid domains")
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
        output = []
        for feed in self.list():
            if not feed["enabled"]:
                continue
            try:
                output.append(self.refresh_one(feed["id"]))
            except Exception as exc:
                output.append({"id": feed["id"], "name": feed["name"], "error": str(exc)})
        return output
