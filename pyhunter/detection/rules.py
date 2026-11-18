"""Loading and validation of YAML detection rules.

Rules live in YAML files, separate from the code. Format (the keys of the
project sheet example are kept as-is)::

    - id: BF-001
      titre: Brute force SSH
      source: auth.log                 # pcap | auth.log | evtx | "*" | list
      condition: echecs_auth >= 10     # clauses joined with "et" / "and"
      fenetre: 60s
      severite: haute                  # faible | moyenne | haute | critique
      attack: T1110.001                # string or list
      # optional:
      description: ...
      kill_chain: exploitation
      groupe_par: [src_ip]             # default [src_ip]
      filtre:  {service: ssh}          # keep only events matching all fields
      exclure: {base_domain: [microsoft.com]}
      ioc: [src_ip]                    # group fields reported as IOC (default [src_ip])
      occurrences_min: 1               # for rules with per-event clauses only
      faux_positifs: ...
      reponse: ...

Conditions are parsed with a small grammar (no ``eval``): unknown metrics,
bad operators or typos in keys are rejected with an explicit error.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from pyhunter.detection.metrics import METRICS, Metric
from pyhunter.models import Event
from pyhunter.utils import parse_duration

SEVERITIES = ("faible", "moyenne", "haute", "critique")
SOURCES = ("pcap", "auth.log", "evtx")
KILL_CHAIN = (
    "reconnaissance", "armement", "livraison", "exploitation",
    "installation", "commande_controle", "actions_objectifs",
)
IOC_TYPES = {"src_ip": "ip", "dst_ip": "ip", "base_domain": "domain", "query": "domain", "user": "user"}
_DOMAIN_FIELDS = {"query", "base_domain"}

_OPS = {">=": operator.ge, "<=": operator.le, "==": operator.eq, "!=": operator.ne,
        ">": operator.gt, "<": operator.lt}
_CLAUSE_RE = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")
_SPLIT_RE = re.compile(r"\s+(?:et|and)\s+", re.IGNORECASE)
_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

REQUIRED_KEYS = {"id", "titre", "source", "condition", "severite"}
ALLOWED_KEYS = REQUIRED_KEYS | {
    "fenetre", "attack", "description", "kill_chain", "groupe_par", "filtre", "exclure",
    "ioc", "occurrences_min", "faux_positifs", "reponse", "active",
}


class RuleError(ValueError):
    """Invalid rule file or rule definition."""


@dataclass(frozen=True)
class Clause:
    metric: Metric
    op: str
    threshold: float

    def test(self, value: float) -> bool:
        return _OPS[self.op](value, self.threshold)

    def __str__(self) -> str:
        threshold = int(self.threshold) if float(self.threshold).is_integer() else self.threshold
        return f"{self.metric.name} {self.op} {threshold}"


@dataclass
class Rule:
    id: str
    titre: str
    sources: tuple[str, ...]
    condition: str
    event_clauses: list[Clause]
    agg_clauses: list[Clause]
    fenetre: timedelta
    severite: str
    attack: list[str] = field(default_factory=list)
    description: str = ""
    kill_chain: str | None = None
    groupe_par: list[str] = field(default_factory=lambda: ["src_ip"])
    filtre: dict[str, Any] = field(default_factory=dict)
    exclure: dict[str, Any] = field(default_factory=dict)
    ioc: list[str] = field(default_factory=lambda: ["src_ip"])
    event_kinds: frozenset[str] | None = None
    faux_positifs: str | None = None
    reponse: str | None = None
    origine: str = ""

    def accepts(self, event: Event) -> bool:
        """Per-event filtering: source, event kind, filtre/exclure, per-event clauses."""
        if "*" not in self.sources and event.source not in self.sources:
            return False
        if self.event_kinds is not None and event.kind not in self.event_kinds:
            return False
        if self.filtre and not all(_field_matches(event, k, v) for k, v in self.filtre.items()):
            return False
        if self.exclure and any(_field_matches(event, k, v) for k, v in self.exclure.items()):
            return False
        return all(c.test(c.metric.compute(event)) for c in self.event_clauses)

    def group_key(self, event: Event) -> tuple | None:
        values = tuple(event.get(name) for name in self.groupe_par)
        return None if any(v is None for v in values) else values

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "titre": self.titre, "source": list(self.sources),
            "condition": self.condition, "fenetre_s": self.fenetre.total_seconds(),
            "severite": self.severite, "attack": self.attack, "kill_chain": self.kill_chain,
            "fichier": self.origine,
        }


def _field_matches(event: Event, name: str, expected: Any) -> bool:
    value = event.get(name)
    if value is None:
        return False
    candidates = expected if isinstance(expected, list) else [expected]
    if name in _DOMAIN_FIELDS:  # suffix match: "microsoft.com" matches "a.b.microsoft.com"
        text = str(value).lower()
        return any(text == str(c).lower() or text.endswith("." + str(c).lower()) for c in candidates)
    return any(str(value) == str(c) for c in candidates)


def parse_condition(text: str) -> list[Clause]:
    clauses = []
    for part in _SPLIT_RE.split(text.strip()):
        match = _CLAUSE_RE.match(part)
        if not match:
            raise RuleError(f"clause invalide « {part} » (attendu : <métrique> <opérateur> <nombre>)")
        name, op, number = match.groups()
        if name not in METRICS:
            raise RuleError(f"métrique inconnue « {name} » ; disponibles : {', '.join(sorted(METRICS))}")
        clauses.append(Clause(METRICS[name], op, float(number)))
    return clauses


def _as_list(value: Any, key: str, rule_id: str) -> list:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        return [value]
    if isinstance(value, list):
        return value
    raise RuleError(f"{rule_id} : « {key} » doit être une valeur ou une liste")


def parse_rule(data: dict[str, Any], origine: str = "") -> Rule | None:
    """Validate one rule mapping. Returns None if the rule is disabled (active: false)."""
    if not isinstance(data, dict):
        raise RuleError(f"{origine} : chaque règle doit être un dictionnaire YAML")
    rule_id = str(data.get("id", "?"))
    where = f"{origine} [{rule_id}]"

    missing = REQUIRED_KEYS - data.keys()
    if missing:
        raise RuleError(f"{where} : champs obligatoires manquants : {', '.join(sorted(missing))}")
    unknown = data.keys() - ALLOWED_KEYS
    if unknown:
        raise RuleError(f"{where} : champs inconnus (faute de frappe ?) : {', '.join(sorted(unknown))}")
    if data.get("active", True) is False:
        return None

    sources = tuple(str(s) for s in _as_list(data["source"], "source", rule_id))
    bad_sources = [s for s in sources if s not in SOURCES and s != "*"]
    if bad_sources or not sources:
        raise RuleError(f"{where} : source invalide {bad_sources} ; valeurs : {', '.join(SOURCES)} ou *")

    severite = str(data["severite"]).lower()
    if severite not in SEVERITIES:
        raise RuleError(f"{where} : sévérité « {severite} » invalide ; valeurs : {', '.join(SEVERITIES)}")

    try:
        clauses = parse_condition(str(data["condition"]))
        fenetre = parse_duration(data.get("fenetre", "60s"))
    except (RuleError, ValueError) as exc:
        raise RuleError(f"{where} : {exc}") from None
    if fenetre.total_seconds() <= 0:
        raise RuleError(f"{where} : la fenêtre doit être strictement positive")

    attack = [str(a).upper() for a in _as_list(data.get("attack"), "attack", rule_id)]
    bad_attack = [a for a in attack if not _ATTACK_RE.match(a)]
    if bad_attack:
        raise RuleError(f"{where} : identifiant ATT&CK invalide {bad_attack} (format T1234 ou T1234.001)")

    kill_chain = data.get("kill_chain")
    if kill_chain is not None and kill_chain not in KILL_CHAIN:
        raise RuleError(f"{where} : phase Kill Chain « {kill_chain} » invalide ; valeurs : {', '.join(KILL_CHAIN)}")

    groupe_par = [str(g) for g in _as_list(data.get("groupe_par", ["src_ip"]), "groupe_par", rule_id)]
    ioc = [str(i) for i in _as_list(data.get("ioc", ["src_ip"]), "ioc", rule_id)]
    not_grouped = [i for i in ioc if i not in groupe_par]
    if not_grouped:
        raise RuleError(f"{where} : les champs IOC {not_grouped} doivent figurer dans groupe_par")

    for key in ("filtre", "exclure"):
        if key in data and not isinstance(data[key], dict):
            raise RuleError(f"{where} : « {key} » doit être un dictionnaire champ: valeur(s)")

    event_clauses = [c for c in clauses if c.metric.family == "event"]
    agg_clauses = [c for c in clauses if c.metric.family == "aggregate"]
    occurrences_min = data.get("occurrences_min")
    if occurrences_min is not None:
        if agg_clauses:
            raise RuleError(f"{where} : occurrences_min n'a de sens que sans métrique agrégée dans la condition")
        if not isinstance(occurrences_min, int) or occurrences_min < 1:
            raise RuleError(f"{where} : occurrences_min doit être un entier >= 1")
    if not agg_clauses:
        agg_clauses = [Clause(METRICS["occurrences"], ">=", float(occurrences_min or 1))]

    kinds: frozenset[str] | None = None
    for clause in clauses:
        if clause.metric.event_kinds is None:
            continue
        kinds = clause.metric.event_kinds if kinds is None else kinds & clause.metric.event_kinds
    if kinds is not None and not kinds:
        raise RuleError(f"{where} : les métriques de la condition portent sur des types d'événements incompatibles")

    condition = " et ".join(str(c) for c in clauses)
    if occurrences_min:
        condition += f" (au moins {occurrences_min} fois)"

    return Rule(
        id=rule_id, titre=str(data["titre"]), sources=sources, condition=condition,
        event_clauses=event_clauses, agg_clauses=agg_clauses, fenetre=fenetre,
        severite=severite, attack=attack, description=str(data.get("description", "")).strip(),
        kill_chain=kill_chain, groupe_par=groupe_par, filtre=dict(data.get("filtre", {})),
        exclure=dict(data.get("exclure", {})), ioc=ioc, event_kinds=kinds,
        faux_positifs=(str(data["faux_positifs"]).strip() if data.get("faux_positifs") else None),
        reponse=(str(data["reponse"]).strip() if data.get("reponse") else None),
        origine=origine,
    )


def _rule_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for path in map(Path, paths):
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.suffix.lower() in (".yml", ".yaml")))
        elif path.is_file():
            files.append(path)
        else:
            raise RuleError(f"chemin de règles introuvable : {path}")
    return files


def load_rules(paths: Iterable[str | Path]) -> list[Rule]:
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for file in _rule_files(paths):
        try:
            document = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleError(f"{file} : YAML invalide : {exc}") from None
        if document is None:
            continue
        items = document if isinstance(document, list) else [document]
        for item in items:
            rule = parse_rule(item, origine=file.name)
            if rule is None:
                continue
            if rule.id in seen:
                raise RuleError(f"identifiant de règle en double « {rule.id} » ({seen[rule.id]} et {file.name})")
            seen[rule.id] = file.name
            rules.append(rule)
    if not rules:
        raise RuleError("aucune règle active trouvée")
    return rules
