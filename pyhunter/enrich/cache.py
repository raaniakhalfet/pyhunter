"""Local SQLite cache for threat-intelligence lookups.

Why: the free VirusTotal API is heavily rate-limited, and the demo must work
without network. Every answer (including "not found") is stored with its date;
entries older than the TTL are refreshed when online, and still used (flagged
as stale) when offline.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ti_cache (
    provider   TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    status     INTEGER NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (provider, ioc_type, value)
)
"""


@dataclass
class CacheEntry:
    status: int
    payload: dict[str, Any]
    fetched_at: datetime
    stale: bool


class Cache:
    def __init__(self, path: str | Path, ttl: timedelta = timedelta(days=7), provider: str = "virustotal") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self.provider = provider
        self.conn = sqlite3.connect(self.path)
        self.conn.execute(_SCHEMA)
        self.conn.commit()

    def get(self, ioc_type: str, value: str, now: datetime | None = None) -> CacheEntry | None:
        row = self.conn.execute(
            "SELECT status, payload, fetched_at FROM ti_cache WHERE provider=? AND ioc_type=? AND value=?",
            (self.provider, ioc_type, value.lower()),
        ).fetchone()
        if row is None:
            return None
        fetched_at = datetime.fromisoformat(row[2])
        now = now or datetime.now(timezone.utc)
        return CacheEntry(row[0], json.loads(row[1]), fetched_at, stale=now - fetched_at > self.ttl)

    def put(self, ioc_type: str, value: str, status: int, payload: dict[str, Any], now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        self.conn.execute(
            "INSERT OR REPLACE INTO ti_cache VALUES (?, ?, ?, ?, ?, ?)",
            (self.provider, ioc_type, value.lower(), status, json.dumps(payload), now.isoformat()),
        )
        self.conn.commit()

    def stats(self) -> dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) FROM ti_cache").fetchone()[0]
        by_type = dict(self.conn.execute("SELECT ioc_type, COUNT(*) FROM ti_cache GROUP BY ioc_type").fetchall())
        return {"fichier": self.path, "entrees": total, "par_type": by_type, "ttl_jours": self.ttl.total_seconds() / 86400}

    def clear(self) -> int:
        count = self.conn.execute("DELETE FROM ti_cache").rowcount
        self.conn.commit()
        return count

    def close(self) -> None:
        self.conn.close()
