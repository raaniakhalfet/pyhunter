"""Metrics usable in a rule ``condition``.

Two families:
  * per-event metrics ("event"): computed on one event, used as a filter
    (e.g. ``entropie_dns >= 3.5``);
  * aggregate metrics ("aggregate"): computed over the sliding time window of
    one group (e.g. ``echecs_auth >= 10`` within 60 s for one source IP).

Aggregates are incremental (add/remove), so a sliding window costs O(1) per
event instead of re-scanning the window — important for large scans.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from pyhunter.models import Event
from pyhunter.utils import shannon_entropy


class CountAgg:
    def __init__(self) -> None:
        self.n = 0

    def add(self, event: Event) -> None:
        self.n += 1

    def remove(self, event: Event) -> None:
        self.n -= 1

    def value(self) -> float:
        return float(self.n)


class DistinctAgg:
    """Number of distinct values of one event field in the window."""

    def __init__(self, field: str) -> None:
        self.field = field
        self.counts: Counter = Counter()

    def add(self, event: Event) -> None:
        value = event.get(self.field)
        if value is not None:
            self.counts[value] += 1

    def remove(self, event: Event) -> None:
        value = event.get(self.field)
        if value is None:
            return
        self.counts[value] -= 1
        if self.counts[value] <= 0:
            del self.counts[value]

    def value(self) -> float:
        return float(len(self.counts))


@dataclass(frozen=True)
class Metric:
    name: str
    family: str  # "event" | "aggregate"
    description: str
    event_kinds: frozenset[str] | None = None  # None = any kind
    factory: Callable[[], CountAgg | DistinctAgg] | None = None
    compute: Callable[[Event], float] | None = None


def _subdomain(event: Event) -> str:
    return (event.extra.get("sous_domaine") or "").replace(".", "")


_AUTH_FAIL = frozenset({"auth_failure"})
_SYN = frozenset({"tcp_syn"})
_DNS = frozenset({"dns_query"})

METRICS: dict[str, Metric] = {
    m.name: m
    for m in [
        Metric("occurrences", "aggregate", "Nombre d'événements retenus dans la fenêtre", None, CountAgg),
        Metric("echecs_auth", "aggregate", "Nombre d'échecs d'authentification dans la fenêtre", _AUTH_FAIL, CountAgg),
        Metric("succes_auth", "aggregate", "Nombre d'authentifications réussies dans la fenêtre",
               frozenset({"auth_success"}), CountAgg),
        Metric("utilisateurs_distincts", "aggregate", "Comptes différents visés dans la fenêtre",
               _AUTH_FAIL, lambda: DistinctAgg("user")),
        Metric("ports_distincts", "aggregate", "Ports TCP différents sondés (SYN) dans la fenêtre",
               _SYN, lambda: DistinctAgg("dst_port")),
        Metric("hotes_distincts", "aggregate", "Hôtes différents sondés (SYN) dans la fenêtre",
               _SYN, lambda: DistinctAgg("dst_ip")),
        Metric("entropie_dns", "event", "Entropie de Shannon du sous-domaine (bits/caractère)",
               _DNS, compute=lambda e: shannon_entropy(_subdomain(e))),
        Metric("longueur_sous_domaine", "event", "Longueur du sous-domaine (sans les points)",
               _DNS, compute=lambda e: float(len(_subdomain(e)))),
        Metric("longueur_requete_dns", "event", "Longueur totale du nom DNS demandé",
               _DNS, compute=lambda e: float(len(e.query or ""))),
    ]
}
