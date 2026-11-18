"""Parser for Linux authentication logs (/var/log/auth.log, /var/log/secure).

Supported formats:
  * classic syslog:  ``Nov 20 09:03:01 srv-web sshd[812]: Failed password ...``
    (no year and no time zone -> both come from the caller)
  * RFC 3339:        ``2026-11-20T09:03:01.123+01:00 srv-web sshd[812]: ...``
  * rsyslog duplicate suppression: ``message repeated 3 times: [ Failed password ...]``

Counted as failures: ``Failed password|publickey|keyboard-interactive|none``.
``Invalid user`` and ``pam_unix ... authentication failure`` lines are NOT counted,
because sshd logs a ``Failed ...`` line for the same attempt (no double counting).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import datetime, timezone, tzinfo
from pathlib import Path

from pyhunter.models import Event
from pyhunter.utils import parse_iso_ts

log = logging.getLogger(__name__)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)
REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times:\s*\[\s*(?P<msg>.*?)\s*\]$")


def iter_authlog(
    path: str | Path,
    year: int | None = None,
    tz: tzinfo = timezone.utc,
    stats: dict | None = None,
) -> Iterator[Event]:
    """Yield auth events from a log file.

    ``year`` and ``tz`` only apply to classic syslog lines, which carry neither.
    """
    stats = stats if stats is not None else {}
    stats.setdefault("lignes", 0)
    stats.setdefault("lignes_ignorees", 0)
    current_year = year or datetime.now(tz).year
    last_month: int | None = None

    with open(path, encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            stats["lignes"] += 1

            match = SYSLOG_RE.match(line)
            if match:
                month = _MONTHS.get(match["mon"])
                if month is None:
                    stats["lignes_ignorees"] += 1
                    continue
                # New year rollover inside one file (Dec -> Jan).
                if last_month is not None and month < last_month and last_month - month > 6:
                    current_year += 1
                last_month = month
                hh, mm, ss = (int(x) for x in match["time"].split(":"))
                local = datetime(current_year, month, int(match["day"]), hh, mm, ss, tzinfo=tz)
                ts = local.astimezone(timezone.utc)
            else:
                match = ISO_RE.match(line)
                if not match:
                    stats["lignes_ignorees"] += 1
                    continue
                ts = parse_iso_ts(match["ts"])

            if not match["prog"].startswith("sshd"):  # sshd, and sshd-session (OpenSSH >= 9.8)
                continue

            yield from _parse_message(match["msg"], ts, match["host"], line, lineno)


def _parse_message(msg: str, ts: datetime, host: str, line: str, lineno: int) -> Iterator[Event]:
    repeat = 1
    rep = REPEAT_RE.match(msg)
    if rep:
        repeat = int(rep["n"])
        msg = rep["msg"]

    failed = FAILED_RE.search(msg)
    if failed:
        for i in range(repeat):
            yield Event(
                ts=ts, source="auth.log", kind="auth_failure",
                src_ip=failed["ip"], src_port=int(failed["port"]),
                user=failed["user"] or None, service="ssh", raw=line,
                extra={
                    "hote": host, "ligne": lineno, "methode": failed["method"],
                    "utilisateur_invalide": bool(failed["invalid"]),
                    **({"repetition": f"{i + 1}/{repeat}"} if repeat > 1 else {}),
                },
            )
        return

    accepted = ACCEPTED_RE.search(msg)
    if accepted:
        yield Event(
            ts=ts, source="auth.log", kind="auth_success",
            src_ip=accepted["ip"], src_port=int(accepted["port"]),
            user=accepted["user"], service="ssh", raw=line,
            extra={"hote": host, "ligne": lineno, "methode": accepted["method"]},
        )
