"""End-to-end pipeline: ingestion -> normalisation -> detection -> correlation
-> enrichment -> report. Kept separate from the CLI so tests can call it."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from datetime import timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pyhunter.detection import correlate, run_rules
from pyhunter.detection.rules import Rule
from pyhunter.enrich import Cache, VTClient, collect_iocs, enrich_iocs
from pyhunter.enrich.iocs import escalate_on_verdict
from pyhunter.ingest import iter_authlog, iter_pcap, iter_windows_events
from pyhunter.models import Alert, Event
from pyhunter.report import build_report
from pyhunter.utils import parse_duration, sha256_file

log = logging.getLogger(__name__)


@dataclass
class Inputs:
    pcaps: list[Path] = field(default_factory=list)
    authlogs: list[Path] = field(default_factory=list)
    evtx: list[Path] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.pcaps or self.authlogs or self.evtx)


@dataclass
class Result:
    report: dict[str, Any]
    alerts: list[Alert]
    events: list[Event]


def load_timezone(name: str | None) -> tzinfo:
    """UTC works everywhere; named zones need the OS database or the tzdata package (Windows)."""
    if not name or name.strip().upper() in ("UTC", "Z", "ETC/UTC", "GMT"):
        return timezone.utc
    try:
        return ZoneInfo(name.strip())
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(
            f"fuseau horaire inconnu « {name} » (exemple : Africa/Tunis). "
            "Sous Windows, installez la base des fuseaux : pip install tzdata"
        ) from None


def ingest(inputs: Inputs, config: dict[str, Any]) -> tuple[list[Event], list[dict[str, Any]]]:
    syslog = config["syslog"]
    tz = load_timezone(syslog.get("fuseau"))
    events: list[Event] = []
    described: list[dict[str, Any]] = []

    jobs = (
        [("pcap", p, lambda p, s: iter_pcap(p, stats=s)) for p in inputs.pcaps]
        + [("auth.log", p, lambda p, s: iter_authlog(p, year=syslog.get("annee"), tz=tz, stats=s)) for p in inputs.authlogs]
        + [("evtx", p, lambda p, s: iter_windows_events(p, stats=s)) for p in inputs.evtx]
    )
    for kind, path, reader in jobs:
        if not Path(path).is_file():
            raise FileNotFoundError(f"fichier introuvable : {path}")
        stats: dict[str, Any] = {}
        before = len(events)
        events.extend(reader(path, stats))
        described.append({
            "type": kind, "fichier": str(path), "sha256": sha256_file(path),
            "evenements": len(events) - before, "statistiques": stats,
        })
        log.info("%s %s : %d événements retenus", kind, path, len(events) - before)
    events.sort(key=lambda e: e.ts)
    return events, described


def analyze(
    inputs: Inputs,
    rules: list[Rule],
    config: dict[str, Any],
    offline: bool = False,
    enrich: bool = True,
    api_key: str | None = None,
    client: VTClient | None = None,
) -> Result:
    events, described = ingest(inputs, config)
    alerts = run_rules(rules, events)
    campaigns = correlate(alerts, events, horizon=parse_duration(config["correlation"]["horizon_succes"]))

    iocs = collect_iocs(alerts)
    vt = config["virustotal"]
    cache = None
    if enrich and client is None:
        cache = Cache(vt["cache"], ttl=parse_duration(vt["ttl"]))
        key = api_key if api_key is not None else os.environ.get(vt["cle_api_env"])
        client = VTClient(
            key, cache, offline=offline,
            min_interval=parse_duration(vt["intervalle_min"]).total_seconds(),
            timeout=parse_duration(vt["timeout"]).total_seconds(),
            max_retries=int(vt["tentatives"]),
        )
    try:
        enrichment = enrich_iocs(iocs, client if enrich else None, enrich_private=bool(vt["enrichir_ip_privees"]))
    finally:
        if cache is not None:
            cache.close()
    escalate_on_verdict(alerts, enrichment)

    mode = "desactive" if not enrich else ("hors_ligne" if offline else "en_ligne")
    report = build_report(
        inputs=described, rules=rules, alerts=alerts, campaigns=campaigns,
        iocs=iocs, enrichment=enrichment, mode=mode, event_count=len(events),
    )
    return Result(report=report, alerts=alerts, events=events)
