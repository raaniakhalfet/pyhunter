"""Sliding-window detection engine.

For each rule, events accepted by the rule are split into groups
(``groupe_par``, e.g. one group per source IP). Each group keeps a sliding
window of length ``fenetre``. When every aggregate clause is true on the
window, an *incident* opens; it keeps absorbing the group's events while they
arrive less than ``fenetre`` apart, then closes and becomes one ``Alert``.
Result: one alert per attack episode, not one alert per packet.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pyhunter.detection.rules import IOC_TYPES, Rule
from pyhunter.models import Alert, Event

SAMPLE_SIZE = 15  # events kept as evidence per alert
DISTINCT_FIELDS = ("dst_port", "dst_ip", "user", "query", "service")
DISTINCT_CAP = 50  # values listed per field in the report


@dataclass
class _Incident:
    first: datetime
    last: datetime
    count: int = 0
    maxima: dict[str, float] = field(default_factory=dict)
    sample: list[Event] = field(default_factory=list)
    distinct: dict[str, dict[Any, int]] = field(default_factory=dict)

    def add(self, event: Event) -> None:
        self.count += 1
        self.last = max(self.last, event.ts)
        if len(self.sample) < SAMPLE_SIZE:
            self.sample.append(event)
        for name in DISTINCT_FIELDS:
            value = event.get(name)
            if value is not None:
                bucket = self.distinct.setdefault(name, {})
                bucket[value] = bucket.get(value, 0) + 1

    def update_maxima(self, values: dict[str, float]) -> None:
        for name, value in values.items():
            self.maxima[name] = max(self.maxima.get(name, value), value)


class _GroupState:
    def __init__(self, rule: Rule, key: tuple) -> None:
        self.rule = rule
        self.key = key
        self.window: deque[Event] = deque()
        self.aggs = {c.metric.name: c.metric.factory() for c in rule.agg_clauses}
        self.current: _Incident | None = None
        self.incidents: list[_Incident] = []

    def push(self, event: Event) -> None:
        fenetre = self.rule.fenetre
        if self.current is not None and event.ts - self.current.last > fenetre:
            self._close()

        self.window.append(event)
        for agg in self.aggs.values():
            agg.add(event)
        while self.window and event.ts - self.window[0].ts > fenetre:
            old = self.window.popleft()
            for agg in self.aggs.values():
                agg.remove(old)

        values = {name: agg.value() for name, agg in self.aggs.items()}
        triggered = all(c.test(values[c.metric.name]) for c in self.rule.agg_clauses)

        if self.current is None:
            if triggered:
                self.current = _Incident(first=self.window[0].ts, last=event.ts)
                for past in self.window:  # the events that built up to the threshold
                    self.current.add(past)
                    self.current.update_maxima(self._event_values(past))
                self.current.update_maxima(values)
        else:
            self.current.add(event)
            self.current.update_maxima(values)
            self.current.update_maxima(self._event_values(event))

    def _event_values(self, event: Event) -> dict[str, float]:
        """Per-event metrics (e.g. entropy), so the report shows the max observed."""
        return {c.metric.name: c.metric.compute(event) for c in self.rule.event_clauses}

    def _close(self) -> None:
        if self.current is not None:
            self.incidents.append(self.current)
            self.current = None

    def finish(self) -> list[_Incident]:
        self._close()
        return self.incidents


def _sort_key(value: Any) -> tuple:
    """Numbers in numeric order, then strings alphabetically (ports 1, 2, 10 — not 1, 10, 2)."""
    return (0, value, "") if isinstance(value, (int, float)) else (1, 0, str(value))


def _to_alert(rule: Rule, key: tuple, incident: _Incident) -> Alert:
    groupe = dict(zip(rule.groupe_par, key))
    iocs = [{"type": IOC_TYPES.get(name, "autre"), "champ": name, "valeur": str(groupe[name])} for name in rule.ioc]
    observed = {}
    for name, bucket in incident.distinct.items():
        if name in rule.groupe_par:
            continue  # constant within the group, already shown
        ranked = sorted(bucket.items(), key=lambda kv: (-kv[1], _sort_key(kv[0])))
        observed[name] = {
            "distincts": len(bucket),
            "valeurs": [v for v, _ in ranked[:DISTINCT_CAP]],
        }
    return Alert(
        rule_id=rule.id, titre=rule.titre, description=rule.description, severite=rule.severite,
        attack=list(rule.attack), kill_chain=rule.kill_chain, condition=rule.condition,
        fenetre_s=rule.fenetre.total_seconds(), groupe=groupe,
        first_seen=incident.first, last_seen=incident.last, event_count=incident.count,
        metriques={k: (int(v) if float(v).is_integer() else round(v, 3)) for k, v in incident.maxima.items()},
        valeurs_observees=observed, iocs=iocs,
        preuves=[e.to_dict() for e in incident.sample],
        faux_positifs=rule.faux_positifs, reponse=rule.reponse,
    )


def run_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    groups: dict[tuple, _GroupState] = {}
    for event in events:
        if not rule.accepts(event):
            continue
        key = rule.group_key(event)
        if key is None:
            continue
        state = groups.get(key)
        if state is None:
            state = groups[key] = _GroupState(rule, key)
        state.push(event)
    alerts = []
    for key, state in groups.items():
        alerts.extend(_to_alert(rule, key, inc) for inc in state.finish())
    return alerts


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    """Run every rule on time-ordered events; return alerts with stable IDs."""
    ordered = sorted(events, key=lambda e: e.ts)
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(run_rule(rule, ordered))
    alerts.sort(key=lambda a: (a.first_seen, a.rule_id, str(a.groupe)))
    for index, alert in enumerate(alerts, start=1):
        alert.alert_id = f"ALR-{index:03d}"
    return alerts
