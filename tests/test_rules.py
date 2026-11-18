from datetime import timedelta

import pytest
import yaml

from conftest import RULES_DIR, ev
from pyhunter.detection.rules import RuleError, load_rules, parse_condition, parse_rule

BASE = {"id": "T-1", "titre": "t", "source": "auth.log", "condition": "echecs_auth >= 10", "severite": "haute"}


def test_project_rules_are_valid():
    rules = load_rules([RULES_DIR])
    assert {r.id for r in rules} >= {"SCAN-001", "BF-001", "BF-002", "BF-003", "DNS-001"}


def test_sheet_example_format_is_supported(tmp_path):
    # Exact example from the project sheet (single-value attack, French keys)
    (tmp_path / "bf.yaml").write_text(
        "- id: BF-001\n  titre: Brute force SSH\n  source: auth.log\n  condition: echecs_auth >= 10\n"
        "  fenetre: 60s\n  severite: haute\n  attack: T1110\n", encoding="utf-8")
    (rule,) = load_rules([tmp_path])
    assert rule.fenetre == timedelta(seconds=60) and rule.attack == ["T1110"]


def test_condition_with_and():
    clauses = parse_condition("entropie_dns >= 3.5 et longueur_sous_domaine > 20")
    assert [str(c) for c in clauses] == ["entropie_dns >= 3.5", "longueur_sous_domaine > 20"]


@pytest.mark.parametrize("override, message", [
    ({"condition": "echecs >= 10"}, "métrique inconnue"),
    ({"condition": "echecs_auth => 10"}, "clause invalide"),
    ({"condition": "__import__('os') >= 1"}, "clause invalide"),
    ({"severite": "urgente"}, "sévérité"),
    ({"source": "syslog"}, "source invalide"),
    ({"fenetre": "dix secondes"}, "durée invalide"),
    ({"attack": "1110"}, "ATT&CK"),
    ({"seuil": 3}, "champs inconnus"),
    ({"kill_chain": "phase9"}, "Kill Chain"),
    ({"ioc": ["user"]}, "groupe_par"),
    ({"condition": "echecs_auth >= 3 et ports_distincts >= 3"}, "incompatibles"),
])
def test_invalid_rules_are_rejected(override, message):
    with pytest.raises(RuleError, match=message):
        parse_rule({**BASE, **override}, "test.yaml")


def test_missing_required_field():
    data = dict(BASE)
    del data["condition"]
    with pytest.raises(RuleError, match="manquants"):
        parse_rule(data)


def test_disabled_rule_is_skipped():
    assert parse_rule({**BASE, "active": False}) is None


def test_duplicate_ids(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(yaml.safe_dump([BASE]), encoding="utf-8")
    with pytest.raises(RuleError, match="double"):
        load_rules([tmp_path])


def test_filters_and_suffix_exclusion():
    rule = parse_rule({**BASE, "source": "pcap", "condition": "longueur_sous_domaine >= 1",
                       "groupe_par": ["src_ip", "base_domain"], "ioc": ["base_domain"],
                       "exclure": {"base_domain": ["cloudfront.net"]}})
    keep = ev(kind="dns_query", source="pcap", src_ip="h", base_domain="evil.com", extra={"sous_domaine": "x"})
    drop = ev(kind="dns_query", source="pcap", src_ip="h", base_domain="d1.cloudfront.net", extra={"sous_domaine": "x"})
    other_source = ev(kind="dns_query", source="auth.log", src_ip="h", base_domain="evil.com", extra={"sous_domaine": "x"})
    assert rule.accepts(keep) and not rule.accepts(drop) and not rule.accepts(other_source)
