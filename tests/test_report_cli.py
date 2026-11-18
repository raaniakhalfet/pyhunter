import json

from conftest import RULES_DIR, ev
from pyhunter.cli import main
from pyhunter.detection import load_rules, run_rules
from pyhunter.detection.rules import parse_rule
from pyhunter.report import build_report, write_html


def test_html_escapes_attacker_controlled_content(tmp_path):
    rule = parse_rule({"id": "BF", "titre": "bf", "source": "auth.log", "condition": "echecs_auth >= 2", "severite": "haute"})
    payload = "<script>alert(1)</script>"
    events = [ev(i, src_ip="10.0.0.5", user=payload, raw=f"Failed password for {payload}") for i in range(3)]
    alerts = run_rules([rule], events)
    report = build_report(inputs=[], rules=[rule], alerts=alerts, campaigns=[], iocs={}, enrichment={},
                          mode="desactive", event_count=3)
    html = write_html(report, tmp_path / "r.html").read_text(encoding="utf-8")
    assert payload not in html and "&lt;script&gt;" in html


def test_cli_end_to_end_on_lab_scenario(lab_data, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # cache file and default config are local to the test
    out = tmp_path / "out"
    code = main(["analyze", "--pcap", str(lab_data / "lab.pcap"), "--authlog", str(lab_data / "auth.log"),
                 "--evtx", str(lab_data / "security.xml"), "--rules", str(RULES_DIR),
                 "--year", "2026", "--offline", "-o", str(out)])
    assert code == 0
    report = json.loads((out / "rapport.json").read_text(encoding="utf-8"))
    by_rule = {a["rule_id"]: a for a in report["alertes"]}
    # Exactly the 4 attack steps of the scenario, and nothing on benign traffic
    assert sorted(by_rule) == ["BF-001", "BF-002", "DNS-001", "SCAN-001"]
    assert by_rule["SCAN-001"]["metriques"]["ports_distincts"] == 1024
    assert by_rule["SCAN-001"]["valeurs_observees"]["ports_ouverts"]["valeurs"] == [22, 80, 443]
    assert by_rule["BF-001"]["nb_evenements"] == 27  # 24 lines + "message repeated 3 times"
    assert by_rule["BF-001"]["compromission"] and by_rule["BF-001"]["severite"] == "critique"
    assert by_rule["DNS-001"]["nb_evenements"] == 40
    assert by_rule["BF-002"]["groupe"] == {"src_ip": "192.168.56.20"}
    assert report["correlations"][0]["ioc"] == "192.168.56.10"
    assert {t["id"] for t in report["attack"]} >= {"T1046", "T1110.001", "T1071.004", "T1078"}
    assert all(len(i["sha256"]) == 64 for i in report["entrees"])
    assert (out / "rapport.html").stat().st_size > 5000
    assert "ALR-004" in capsys.readouterr().out


def test_cli_requires_an_input(capsys):
    assert main(["analyze"]) == 2


def test_cli_reports_invalid_rules(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text("- id: X\n  titre: x\n  source: pcap\n  condition: foo > 1\n  severite: haute\n")
    assert main(["rules", "validate", "-r", str(tmp_path)]) == 1
    assert "métrique inconnue" in capsys.readouterr().err


def test_cli_rules_list(capsys):
    assert main(["rules", "list", "-r", str(RULES_DIR)]) == 0
    assert "BF-001" in capsys.readouterr().out


def test_html_renders_virustotal_verdicts(tmp_path):
    rule = parse_rule({"id": "BF", "titre": "bf", "source": "auth.log", "condition": "echecs_auth >= 2", "severite": "haute"})
    alerts = run_rules([rule], [ev(i, src_ip="45.33.32.156", user="root") for i in range(3)])
    enrichment = {("ip", "45.33.32.156"): {
        "statut": "ok", "verdict": "malveillant", "malveillant": 12, "suspect": 1, "inoffensif": 50,
        "non_detecte": 20, "pays": "NL", "proprietaire_as": "Example AS", "origine": "cache",
        "lien": "https://www.virustotal.com/gui/ip-address/45.33.32.156"}}
    report = build_report(inputs=[], rules=[rule], alerts=alerts, campaigns=[],
                          iocs={("ip", "45.33.32.156"): ["ALR-001"]}, enrichment=enrichment,
                          mode="en_ligne", event_count=3)
    html = write_html(report, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "12 malveillant" in html and "virustotal.com/gui/ip-address/45.33.32.156" in html
