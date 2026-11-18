"""Windows Security log parser: logon failures (4625) and successes (4624).

Two input formats:
  * ``.evtx`` binary files, through python-evtx (``pip install python-evtx``);
  * ``.xml`` exports, e.g. from the lab VM:
        wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:xml > security.xml
    (wevtutil writes one <Event> after another with no root element; handled.)
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from pyhunter.models import Event
from pyhunter.utils import parse_iso_ts

log = logging.getLogger(__name__)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
WANTED_IDS = {"4624": "auth_success", "4625": "auth_failure"}

# Logon types: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
LOGON_TYPES = {
    "2": "interactif", "3": "reseau", "4": "batch", "5": "service",
    "7": "deverrouillage", "8": "reseau_clair", "9": "nouvelles_infos",
    "10": "rdp", "11": "cache",
}
# Most frequent 4625 sub-status codes, to explain *why* the logon failed.
FAILURE_REASONS = {
    "0xc000006a": "mot de passe incorrect",
    "0xc0000064": "utilisateur inexistant",
    "0xc0000234": "compte verrouillé",
    "0xc0000072": "compte désactivé",
    "0xc000006f": "hors plage horaire autorisée",
    "0xc0000070": "poste de travail non autorisé",
    "0xc0000071": "mot de passe expiré",
}


def parse_record_xml(xml: str) -> Event | None:
    """Turn one <Event> XML document into an ``Event`` (None if not 4624/4625)."""
    root = ET.fromstring(xml)
    event_id = (root.findtext("e:System/e:EventID", namespaces=NS) or "").strip()
    kind = WANTED_IDS.get(event_id)
    if kind is None:
        return None

    created = root.find("e:System/e:TimeCreated", NS)
    if created is None or not created.get("SystemTime"):
        return None
    ts = parse_iso_ts(created.get("SystemTime"))
    computer = root.findtext("e:System/e:Computer", namespaces=NS)
    data = {d.get("Name"): (d.text or "").strip() for d in root.findall("e:EventData/e:Data", NS)}

    ip = data.get("IpAddress") or None
    if ip in ("-", "::1", "127.0.0.1"):
        ip = None  # local logon, not a remote source
    port = data.get("IpPort")
    logon_type = data.get("LogonType", "")
    user = data.get("TargetUserName") or None
    domain = data.get("TargetDomainName")
    sub_status = (data.get("SubStatus") or "").lower()

    extra = {
        "event_id": int(event_id),
        "ordinateur": computer,
        "type_ouverture": logon_type,
        "poste_source": data.get("WorkstationName"),
        "domaine": domain,
    }
    if kind == "auth_failure":
        extra["status"] = data.get("Status")
        extra["sous_status"] = data.get("SubStatus")
        extra["raison"] = FAILURE_REASONS.get(sub_status, "autre")

    raw = (
        f"EventID={event_id} Computer={computer} User={domain}\\{user} "
        f"IP={data.get('IpAddress')} LogonType={logon_type}"
        + (f" SubStatus={data.get('SubStatus')}" if kind == "auth_failure" else "")
    )
    return Event(
        ts=ts, source="evtx", kind=kind,
        src_ip=ip, src_port=int(port) if port and port.isdigit() and port != "0" else None,
        user=user, service=LOGON_TYPES.get(logon_type, f"type_{logon_type}" if logon_type else None),
        raw=raw, extra={k: v for k, v in extra.items() if v not in (None, "")},
    )


def _iter_xml_export(path: Path) -> Iterator[str]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    text = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    if not text.startswith("<Events"):
        text = f"<Events>{text}</Events>"
    root = ET.fromstring(text)
    for node in root:
        if node.tag.endswith("Event"):
            yield ET.tostring(node, encoding="unicode")


def _iter_evtx_binary(path: Path) -> Iterator[str]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "La lecture des fichiers .evtx nécessite python-evtx : pip install python-evtx "
            "(ou exportez le journal en XML avec wevtutil)."
        ) from exc
    with evtx.Evtx(str(path)) as log_file:
        for record in log_file.records():
            try:
                yield record.xml()
            except Exception as exc:  # corrupted record: skip, keep going
                log.warning("%s : enregistrement illisible ignoré (%s)", path, exc)


def iter_windows_events(path: str | Path, stats: dict | None = None) -> Iterator[Event]:
    path = Path(path)
    stats = stats if stats is not None else {}
    stats.setdefault("enregistrements", 0)
    source = _iter_xml_export(path) if path.suffix.lower() == ".xml" else _iter_evtx_binary(path)
    for xml in source:
        stats["enregistrements"] += 1
        try:
            event = parse_record_xml(xml)
        except ET.ParseError as exc:
            log.warning("%s : XML invalide ignoré (%s)", path, exc)
            continue
        if event is not None:
            yield event
