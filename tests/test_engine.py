from conftest import RULES_DIR, ev
from pyhunter.detection import correlate, load_rules, run_rules
from pyhunter.detection.rules import parse_rule

BF = parse_rule({"id": "BF", "titre": "bf", "source": "auth.log", "condition": "echecs_auth >= 10",
                 "fenetre": "60s", "severite": "haute", "filtre": {"service": "ssh"}})


def failures(n, step, ip="10.0.0.5", start=0, **kw):
    return [ev(start + i * step, src_ip=ip, user="root", **kw) for i in range(n)]


def test_threshold_reached_triggers_one_alert():
    alerts = run_rules([BF], failures(12, 2))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.event_count == 12 and a.metriques["echecs_auth"] == 12
    assert a.groupe == {"src_ip": "10.0.0.5"} and a.iocs[0]["valeur"] == "10.0.0.5"


def test_below_threshold_no_alert():
    assert run_rules([BF], failures(9, 2)) == []


def test_slow_attempts_outside_window_no_alert():
    # 10 failures but 10 s apart: never 10 within 60 s
    assert run_rules([BF], failures(10, 10)) == []


def test_groups_are_independent():
    events = failures(6, 1, ip="10.0.0.5") + failures(6, 1, ip="10.0.0.6")
    assert run_rules([BF], events) == []


def test_two_episodes_two_alerts():
    events = failures(10, 1) + failures(10, 1, start=600)
    alerts = run_rules([BF], events)
    assert len(alerts) == 2 and [a.alert_id for a in alerts] == ["ALR-001", "ALR-002"]


def test_filter_excludes_other_services():
    assert run_rules([BF], failures(12, 1, service="rdp")) == []


def test_scan_rule_counts_distinct_ports():
    rules = [r for r in load_rules([RULES_DIR]) if r.id == "SCAN-001"]
    same_port = [ev(i * 0.01, kind="tcp_syn", source="pcap", src_ip="a", dst_ip="b", dst_port=443) for i in range(100)]
    assert run_rules(rules, same_port) == []  # 100 SYN on one port is not a scan
    scan = [ev(p * 0.01, kind="tcp_syn", source="pcap", src_ip="a", dst_ip="b", dst_port=p) for p in range(1, 101)]
    (alert,) = run_rules(rules, scan)
    assert alert.metriques["ports_distincts"] == 100
    assert alert.valeurs_observees["dst_port"]["valeurs"][:3] == [1, 2, 3]  # numeric order


def test_dns_rule_needs_repeated_high_entropy():
    rules = [r for r in load_rules([RULES_DIR]) if r.id == "DNS-001"]

    def q(i, sub, domain="evil.com"):
        return ev(i, kind="dns_query", source="pcap", src_ip="h", base_domain=domain,
                  query=f"{sub}.{domain}", extra={"sous_domaine": sub})

    randoms = ["26k6qcdctricbjjugyiximlkhsimqtg" + c for c in "abcdefghijkl"]
    assert run_rules(rules, [q(i, s) for i, s in enumerate(randoms[:9])]) == []  # < occurrences_min
    assert len(run_rules(rules, [q(i, s) for i, s in enumerate(randoms)])) == 1
    assert run_rules(rules, [q(i, "www") for i in range(50)]) == []  # low entropy
    assert run_rules(rules, [q(i, s, "d1.cloudfront.net") for i, s in enumerate(randoms)]) == []  # whitelisted


def test_success_after_brute_force_escalates():
    events = failures(12, 1) + [ev(20, kind="auth_success", src_ip="10.0.0.5", user="webadmin", extra={"hote": "srv"})]
    alerts = run_rules([BF], events)
    correlate(alerts, events)
    a = alerts[0]
    assert a.compromission and a.severite == "critique" and "T1078" in a.attack
    assert any("webadmin" in n for n in a.notes)


def test_success_from_other_ip_does_not_escalate():
    events = failures(12, 1) + [ev(20, kind="auth_success", src_ip="10.0.0.99", user="rania")]
    alerts = run_rules([BF], events)
    correlate(alerts, events)
    assert not alerts[0].compromission and alerts[0].severite == "haute"


def test_campaign_same_source_and_open_ports():
    rules = load_rules([RULES_DIR])
    events = [ev(p * 0.01, kind="tcp_syn", source="pcap", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=p)
              for p in range(1, 51)]
    events.append(ev(0.2, kind="tcp_synack", source="pcap", src_ip="10.0.0.9", dst_ip="10.0.0.5", src_port=22, dst_port=5555))
    events += failures(12, 1, start=30)
    alerts = run_rules(rules, events)
    campaigns = correlate(alerts, events)
    assert len(campaigns) == 1
    assert campaigns[0]["phases_kill_chain"] == ["reconnaissance", "exploitation"]
    scan = next(a for a in alerts if a.rule_id == "SCAN-001")
    assert scan.valeurs_observees["ports_ouverts"]["valeurs"] == [22]
