"""Command-line interface.

    pyhunter analyze --pcap capture.pcap --authlog auth.log --evtx security.xml -o out/
    pyhunter rules list | validate
    pyhunter cache stats | clear
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from pyhunter import __version__
from pyhunter.config import load_config
from pyhunter.detection.rules import RuleError, load_rules
from pyhunter.enrich.cache import Cache
from pyhunter.pipeline import Inputs, analyze
from pyhunter.report import write_html, write_json
from pyhunter.utils import parse_duration

SEV_ICON = {"critique": "!!!", "haute": "!! ", "moyenne": "!  ", "faible": ".  "}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyhunter", description="Analyse de PCAP et de journaux, sans SIEM.")
    parser.add_argument("--version", action="version", version=f"PyHunter {__version__}")
    parser.add_argument("-c", "--config", help="fichier de configuration YAML (défaut : ./pyhunter.yaml s'il existe)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="-v infos, -vv débogage")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyser des captures et des journaux")
    a.add_argument("--pcap", action="append", default=[], type=Path, help="capture PCAP/PCAPNG (répétable)")
    a.add_argument("--authlog", action="append", default=[], type=Path, help="journal auth.log / secure (répétable)")
    a.add_argument("--evtx", action="append", default=[], type=Path, help="journal Security .evtx ou export XML wevtutil (répétable)")
    a.add_argument("-r", "--rules", action="append", type=Path, help="fichier ou dossier de règles YAML (défaut : config)")
    a.add_argument("-o", "--out", type=Path, default=Path("rapport"), help="dossier de sortie (défaut : rapport/)")
    a.add_argument("--offline", action="store_true", help="enrichissement depuis le cache local uniquement")
    a.add_argument("--no-enrich", action="store_true", help="aucun enrichissement Threat Intelligence")
    a.add_argument("--year", type=int, help="année des lignes syslog (sans année)")
    a.add_argument("--tz", help="fuseau horaire des lignes syslog, ex. Africa/Tunis")

    r = sub.add_parser("rules", help="lister ou valider les règles")
    r.add_argument("action", choices=["list", "validate"])
    r.add_argument("-r", "--rules", action="append", type=Path)

    c = sub.add_parser("cache", help="gérer le cache d'enrichissement")
    c.add_argument("action", choices=["stats", "clear"])
    return parser


def _cmd_analyze(args, config) -> int:
    inputs = Inputs(pcaps=args.pcap, authlogs=args.authlog, evtx=args.evtx)
    if inputs.is_empty():
        print("erreur : indiquez au moins une entrée (--pcap, --authlog ou --evtx)", file=sys.stderr)
        return 2
    if args.year:
        config["syslog"]["annee"] = args.year
    if args.tz:
        config["syslog"]["fuseau"] = args.tz
    rules = load_rules(args.rules or config["regles"])

    result = analyze(inputs, rules, config, offline=args.offline, enrich=not args.no_enrich)
    json_path = write_json(result.report, args.out / "rapport.json")
    html_path = write_html(result.report, args.out / "rapport.html")

    s = result.report["synthese"]
    print(f"\n{s['evenements_normalises']} événements analysés, {len(rules)} règles, {s['alertes']} alerte(s)")
    for alert in result.alerts:
        group = ", ".join(f"{k}={v}" for k, v in alert.groupe.items())
        flag = "  [COMPROMISSION]" if alert.compromission else ""
        print(f"  {SEV_ICON[alert.severite]} {alert.alert_id} {alert.severite:<8} {alert.rule_id:<9} "
              f"{alert.first_seen:%Y-%m-%d %H:%M:%S}  {alert.titre} ({group}){flag}")
    print(f"\nRapport JSON : {json_path}\nRapport HTML : {html_path}")
    return 0


def _cmd_rules(args, config) -> int:
    rules = load_rules(args.rules or config["regles"])
    if args.action == "validate":
        print(f"{len(rules)} règle(s) valide(s) : {', '.join(r.id for r in rules)}")
        return 0
    for rule in rules:
        print(f"{rule.id:<9} {rule.severite:<8} {','.join(rule.sources):<14} "
              f"[{rule.condition}] / {int(rule.fenetre.total_seconds())}s  {rule.titre}  ({', '.join(rule.attack)})")
    return 0


def _cmd_cache(args, config) -> int:
    vt = config["virustotal"]
    cache = Cache(vt["cache"], ttl=parse_duration(vt["ttl"]))
    try:
        if args.action == "clear":
            print(f"{cache.clear()} entrée(s) supprimée(s)")
        else:
            for key, value in cache.stats().items():
                print(f"{key} : {value}")
    finally:
        cache.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s : %(message)s")
    try:
        config = load_config(args.config)
        handler = {"analyze": _cmd_analyze, "rules": _cmd_rules, "cache": _cmd_cache}[args.command]
        return handler(args, config)
    except (RuleError, FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
