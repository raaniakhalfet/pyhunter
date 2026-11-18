"""Post-detection correlation: turns isolated alerts into an attack story.

1. Success after brute force: an ``auth_success`` from the attacking IP during
   or shortly after a brute-force episode means the account was probably
   compromised -> severity raised to "critique", T1078 (Valid Accounts) added.
2. Scan results: probed ports that answered SYN-ACK are listed as open.
3. Same source: one IP behind several different rules (e.g. scan then brute
   force) is reported as a campaign, ordered along the Kill Chain.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from pyhunter.detection.rules import KILL_CHAIN
from pyhunter.models import Alert, Event

BRUTE_FORCE_METRICS = {"echecs_auth", "utilisateurs_distincts"}
SUCCESS_HORIZON = timedelta(minutes=30)


def correlate(alerts: list[Alert], events: list[Event], horizon: timedelta = SUCCESS_HORIZON) -> list[dict]:
    successes: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "auth_success" and event.src_ip:
            successes[event.src_ip].append(event)
    for items in successes.values():
        items.sort(key=lambda e: e.ts)

    for alert in alerts:
        if not BRUTE_FORCE_METRICS & alert.metriques.keys():
            continue
        ip = alert.groupe.get("src_ip")
        hits = [s for s in successes.get(ip, []) if alert.first_seen <= s.ts <= alert.last_seen + horizon]
        if not hits:
            continue
        first = hits[0]
        alert.compromission = True
        if alert.severite != "critique":
            alert.notes.append(f"Sévérité relevée de « {alert.severite} » à « critique » (connexion réussie).")
            alert.severite = "critique"
        if "T1078" not in alert.attack:
            alert.attack.append("T1078")
        where = first.extra.get("hote") or first.extra.get("ordinateur") or "la cible"
        alert.notes.append(
            f"Connexion RÉUSSIE du compte « {first.user} » depuis {ip} sur {where} à "
            f"{first.ts:%Y-%m-%d %H:%M:%S} UTC, après {alert.event_count} échecs : compromission probable."
        )
        alert.preuves.append({**first.to_dict(), "correlation": "succes_apres_brute_force"})

    # Scan results: which probed ports answered SYN-ACK (= open, exposed to the attacker).
    synacks = [e for e in events if e.kind == "tcp_synack"]
    for alert in alerts:
        if "ports_distincts" not in alert.metriques:
            continue
        scanner, target = alert.groupe.get("src_ip"), alert.groupe.get("dst_ip")
        if not scanner:
            continue
        end = alert.last_seen + timedelta(seconds=5)
        open_ports = sorted({
            e.src_port for e in synacks
            if e.dst_ip == scanner and (target is None or e.src_ip == target)
            and alert.first_seen <= e.ts <= end and e.src_port is not None
        })
        if open_ports:
            alert.valeurs_observees["ports_ouverts"] = {"distincts": len(open_ports), "valeurs": open_ports}
            alert.notes.append(
                f"Ports ouverts découverts par le scan (réponse SYN-ACK) : {', '.join(map(str, open_ports))}."
            )

    # Campaigns: one source IP behind several rules.
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        for ioc in alert.iocs:
            if ioc["type"] == "ip":
                by_ip[ioc["valeur"]].append(alert)

    order = {phase: i for i, phase in enumerate(KILL_CHAIN)}
    campaigns = []
    for ip, items in sorted(by_ip.items()):
        if len({a.rule_id for a in items}) < 2:
            continue
        items.sort(key=lambda a: (a.first_seen, order.get(a.kill_chain or "", 99)))
        ids = [a.alert_id for a in items]
        phases = []
        for a in items:
            if a.kill_chain and a.kill_chain not in phases:
                phases.append(a.kill_chain)
        for a in items:
            others = ", ".join(i for i in ids if i != a.alert_id)
            a.notes.append(f"Même source {ip} impliquée dans : {others}.")
        campaigns.append({
            "ioc": ip,
            "alertes": ids,
            "phases_kill_chain": phases,
            "debut": items[0].first_seen.isoformat(),
            "fin": max(a.last_seen for a in items).isoformat(),
            "compromission": any(a.compromission for a in items),
        })
    return campaigns
