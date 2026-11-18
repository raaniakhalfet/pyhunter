"""Small helpers: entropy, durations, domains, IP classification, timestamps."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Second-level public suffixes we care about (no full Public Suffix List needed
# for a lab tool; extend if your data uses others).
_TWO_LEVEL_SUFFIXES = frozenset(
    {
        "com.tn", "org.tn", "edu.tn", "gov.tn", "nat.tn", "ens.tn", "rnu.tn",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au", "co.jp", "com.br", "co.in", "co.za",
    }
)

# TLDs reserved by RFC 2606 / RFC 6761 / common lab usage: never sent to VirusTotal.
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost", "local", "lab", "lan", "internal", "home", "corp"})

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$", re.IGNORECASE)
_DURATION_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for an empty string)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_domain(name: str) -> tuple[str, str]:
    """Split a DNS name into (subdomain, registered domain).

    >>> split_domain("a1b2.tunnel.evil.com")
    ('a1b2.tunnel', 'evil.com')
    >>> split_domain("www.tek-up.com.tn")
    ('www', 'tek-up.com.tn')
    """
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    if len(labels) <= 2:
        return "", ".".join(labels)
    keep = 3 if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[:-keep]), ".".join(labels[-keep:])


def parse_duration(value: str | int | float) -> timedelta:
    """Parse '60s', '5m', '1h', '1.5s', '500ms' or a number of seconds."""
    if isinstance(value, bool):
        raise ValueError(f"durée invalide : {value!r}")
    if isinstance(value, (int, float)):
        if value < 0:
            raise ValueError(f"durée négative : {value!r}")
        return timedelta(seconds=value)
    match = _DURATION_RE.match(str(value))
    if not match:
        raise ValueError(f"durée invalide : {value!r} (exemples : 30s, 5m, 1h)")
    number, unit = match.groups()
    return timedelta(seconds=float(number) * _DURATION_UNITS[unit.lower() if unit else None])


def is_public_ip(value: str) -> bool:
    """True for globally routable addresses (False for RFC 1918, loopback, TEST-NET...)."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_reserved_domain(domain: str) -> bool:
    tld = domain.lower().rstrip(".").rsplit(".", 1)[-1]
    return tld in RESERVED_TLDS


def parse_iso_ts(value: str) -> datetime:
    """Parse the timestamp variants found in EVTX/XML and RFC 3339 syslog.

    Handles '2026-11-20T09:10:00.1234567Z' (7-digit Windows fractions),
    '2026-11-20 09:10:00.123456+00:00' (python-evtx) and naive values (UTC).
    """
    text = value.strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    match = re.match(r"^(.*?\.\d{6})\d*(.*)$", text)  # truncate fractions > 6 digits
    if match:
        text = match.group(1) + match.group(2)
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
