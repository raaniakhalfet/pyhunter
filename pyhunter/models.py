"""Common data model shared by every stage of the pipeline.

Every parser (PCAP, auth.log, EVTX) converts its input into ``Event`` objects
with the same schema, so detection rules never depend on the input format.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    """One normalised observation (a packet, a log line, an EVTX record)."""

    ts: datetime  # always timezone-aware, UTC
    source: str  # "pcap" | "auth.log" | "evtx"
    kind: str  # tcp_syn | tcp_synack | dns_query | auth_failure | auth_success
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    service: str | None = None  # ssh, rdp, reseau...
    query: str | None = None  # full DNS name
    base_domain: str | None = None  # registered domain of the DNS name
    raw: str = ""  # original line / packet summary, kept as evidence
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Return a schema field, or a value from ``extra``."""
        if name in EVENT_FIELDS:
            return getattr(self, name)
        return self.extra.get(name)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ts": self.ts.isoformat()}
        for name in EVENT_FIELDS:
            if name in ("ts", "extra"):
                continue
            value = getattr(self, name)
            if value not in (None, ""):
                out[name] = value
        if self.extra:
            out["extra"] = dict(self.extra)
        return out


EVENT_FIELDS = frozenset(f.name for f in fields(Event))


@dataclass
class Alert:
    """A rule match: one attack episode for one group (e.g. one source IP)."""

    rule_id: str
    titre: str
    description: str
    severite: str
    attack: list[str]
    kill_chain: str | None
    condition: str
    fenetre_s: float
    groupe: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    metriques: dict[str, float]
    valeurs_observees: dict[str, dict[str, Any]]
    iocs: list[dict[str, str]]
    preuves: list[dict[str, Any]]
    faux_positifs: str | None = None
    reponse: str | None = None
    alert_id: str = ""
    compromission: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "titre": self.titre,
            "description": self.description,
            "severite": self.severite,
            "attack": list(self.attack),
            "kill_chain": self.kill_chain,
            "condition": self.condition,
            "fenetre_s": self.fenetre_s,
            "groupe": dict(self.groupe),
            "debut": self.first_seen.isoformat(),
            "fin": self.last_seen.isoformat(),
            "duree_s": round((self.last_seen - self.first_seen).total_seconds(), 3),
            "nb_evenements": self.event_count,
            "metriques": dict(self.metriques),
            "valeurs_observees": self.valeurs_observees,
            "iocs": list(self.iocs),
            "compromission": self.compromission,
            "notes": list(self.notes),
            "faux_positifs": self.faux_positifs,
            "reponse": self.reponse,
            "preuves": list(self.preuves),
        }
