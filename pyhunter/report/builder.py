"""Build the JSON report (single source of truth) and render it as HTML."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pyhunter import __version__
from pyhunter.detection.rules import SEVERITIES, Rule
from pyhunter.models import Alert
from pyhunter.report.attack import KILL_CHAIN_LABELS, technique

TEMPLATES = Path(__file__).parent / "templates"


def build_report(
    *,
    inputs: list[dict[str, Any]],
    rules: list[Rule],
    alerts: list[Alert],
    campaigns: list[dict[str, Any]],
    iocs: dict[tuple[str, str], list[str]],
    enrichment: dict[tuple[str, str], dict[str, Any]],
    mode: str,
    event_count: int,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    severities = Counter(a.severite for a in alerts)

    attack_rows: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        for tid in alert.attack:
            row = attack_rows.setdefault(tid, {**technique(tid), "alertes": []})
            row["alertes"].append(alert.alert_id)

    period = None
    if alerts:
        period = {
            "debut": min(a.first_seen for a in alerts).isoformat(),
            "fin": max(a.last_seen for a in alerts).isoformat(),
        }

    return {
        "outil": {"nom": "PyHunter", "version": __version__},
        "genere_le": generated_at.isoformat(),
        "mode_enrichissement": mode,
        "entrees": inputs,
        "regles": [r.summary() for r in rules],
        "synthese": {
            "evenements_normalises": event_count,
            "alertes": len(alerts),
            "par_severite": {s: severities.get(s, 0) for s in reversed(SEVERITIES)},
            "compromissions": sum(1 for a in alerts if a.compromission),
            "ioc": len(iocs),
            "periode": period,
        },
        "alertes": [a.to_dict() for a in alerts],
        "ioc": [
            {"type": t, "valeur": v, "alertes": ids, "enrichissement": enrichment.get((t, v), {})}
            for (t, v), ids in iocs.items()
        ],
        "attack": sorted(attack_rows.values(), key=lambda r: r["id"]),
        "correlations": campaigns,
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _fmt_ts(value: str | None) -> str:
    if not value:
        return "—"
    return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "j2"]),  # log content is attacker-controlled: always escape
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ts"] = _fmt_ts
    env.globals["kill_chain_label"] = lambda k: KILL_CHAIN_LABELS.get(k or "", k or "—")
    env.globals["technique"] = technique
    html = env.get_template("report.html.j2").render(r=report)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
