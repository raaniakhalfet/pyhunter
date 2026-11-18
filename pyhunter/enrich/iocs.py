"""Collect IOCs from alerts and enrich them."""

from __future__ import annotations

from typing import Any

from pyhunter.detection.rules import SEVERITIES
from pyhunter.enrich.virustotal import VTClient
from pyhunter.models import Alert
from pyhunter.utils import is_public_ip, is_reserved_domain


def collect_iocs(alerts: list[Alert]) -> dict[tuple[str, str], list[str]]:
    """{(type, value): [alert ids]} — deduplicated, in order of first appearance."""
    iocs: dict[tuple[str, str], list[str]] = {}
    for alert in alerts:
        for ioc in alert.iocs:
            key = (ioc["type"], ioc["valeur"])
            ids = iocs.setdefault(key, [])
            if alert.alert_id not in ids:
                ids.append(alert.alert_id)
    return iocs


def enrich_iocs(
    iocs: dict[tuple[str, str], list[str]],
    client: VTClient | None,
    enrich_private: bool = False,
) -> dict[tuple[str, str], dict[str, Any]]:
    results: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc_type, value in iocs:
        if client is None:
            result = {"statut": "desactive", "detail": "enrichissement désactivé (--no-enrich)"}
        elif ioc_type == "ip" and not enrich_private and not is_public_ip(value):
            result = {"statut": "ignore", "detail": "adresse privée ou réservée : non soumise à VirusTotal"}
        elif ioc_type == "domain" and is_reserved_domain(value):
            result = {"statut": "ignore", "detail": "domaine réservé (.test, .lab, .local…) : non soumis à VirusTotal"}
        else:
            result = client.lookup(ioc_type, value)
        results[(ioc_type, value)] = result
    return results


def escalate_on_verdict(alerts: list[Alert], enrichment: dict[tuple[str, str], dict[str, Any]]) -> None:
    """Raise an alert's severity one level when one of its IOCs is known as malicious."""
    for alert in alerts:
        for ioc in alert.iocs:
            result = enrichment.get((ioc["type"], ioc["valeur"]), {})
            if result.get("verdict") != "malveillant":
                continue
            level = SEVERITIES.index(alert.severite)
            if level < len(SEVERITIES) - 1:
                new = SEVERITIES[level + 1]
                alert.notes.append(
                    f"Sévérité relevée de « {alert.severite} » à « {new} » : {ioc['valeur']} signalé "
                    f"malveillant par {result.get('malveillant')} moteurs VirusTotal."
                )
                alert.severite = new
            break
