#!/usr/bin/env python3
"""Generate a deterministic, fully synthetic lab dataset (no real traffic).

Scenario (2026-11-20, UTC) — see samples/SCENARIO.md:
  09:02  192.168.56.10 SYN-scans srv-web (192.168.56.20), ports 1-1024
  09:03  192.168.56.10 brute-forces SSH on srv-web, then logs in as "webadmin"
  09:06  srv-web runs a DNS tunnel towards *.exfil-lab.test
  09:10  srv-web brute-forces RDP on PC-RH-07 (192.168.56.40) — lateral movement
Benign background traffic and one legitimate failed login are mixed in, to
check that the rules do not fire on normal activity.

Usage:  python scripts/generate_lab_data.py --out samples --seed 42
"""

from __future__ import annotations

import argparse
import base64
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

T0 = datetime(2026, 11, 20, 8, 45, tzinfo=timezone.utc)

ATTACKER = "192.168.56.10"
SRV_WEB = "192.168.56.20"
PC_RH = "192.168.56.40"
WORKSTATION = "192.168.56.50"
ADMIN_PC = "192.168.56.1"
RESOLVER = "192.168.56.2"
OPEN_PORTS = {22, 80, 443}
BENIGN_DOMAINS = [
    "www.google.com", "github.com", "pypi.org", "fonts.googleapis.com", "www.tek-up.de",
    "update.microsoft.com", "outlook.office365.com", "security.ubuntu.com", "api.github.com",
    "cdn.jsdelivr.net", "www.wikipedia.org", "login.microsoftonline.com",
]


def at(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


def _pkt(ts: datetime, layer):
    pkt = Ether() / layer
    pkt.time = ts.timestamp()
    return pkt


def build_pcap(rng: random.Random) -> list:
    pkts = []
    # Background: browsing from a workstation and updates from srv-web (08:45 -> 09:15).
    t = at(0)
    while t < at(30):
        host = rng.choice([WORKSTATION, WORKSTATION, SRV_WEB])
        name = rng.choice(BENIGN_DOMAINS)
        sport = rng.randint(30000, 60000)
        pkts.append(_pkt(t, IP(src=host, dst=RESOLVER) / UDP(sport=sport, dport=53)
                         / DNS(id=rng.randint(0, 65535), rd=1, qd=DNSQR(qname=name))))
        server = f"203.0.113.{rng.randint(10, 200)}"
        cport = rng.randint(40000, 60000)
        pkts.append(_pkt(t + timedelta(milliseconds=30), IP(src=host, dst=server) / TCP(sport=cport, dport=443, flags="S")))
        pkts.append(_pkt(t + timedelta(milliseconds=60), IP(src=server, dst=host) / TCP(sport=443, dport=cport, flags="SA")))
        t += timedelta(seconds=rng.uniform(8, 20))

    # 09:02 SYN scan, shuffled ports 1-1024, ~4 ms apart.
    t = at(17)
    ports = list(range(1, 1025))
    rng.shuffle(ports)
    sport = 54321
    for port in ports:
        pkts.append(_pkt(t, IP(src=ATTACKER, dst=SRV_WEB) / TCP(sport=sport, dport=port, flags="S")))
        reply = "SA" if port in OPEN_PORTS else "RA"
        pkts.append(_pkt(t + timedelta(microseconds=400), IP(src=SRV_WEB, dst=ATTACKER) / TCP(sport=port, dport=sport, flags=reply)))
        t += timedelta(milliseconds=4)

    # 09:06 DNS tunnel from srv-web: 40 queries, 3 s apart, base32-encoded chunks.
    t = at(21)
    for i in range(40):
        chunk = base64.b32encode(rng.randbytes(20)).decode().rstrip("=").lower()  # 32 chars
        name = f"{chunk}.{i:02d}.t.exfil-lab.test"
        pkts.append(_pkt(t, IP(src=SRV_WEB, dst=RESOLVER) / UDP(sport=rng.randint(30000, 60000), dport=53)
                         / DNS(id=rng.randint(0, 65535), rd=1, qd=DNSQR(qname=name, qtype="TXT"))))
        t += timedelta(seconds=3)

    pkts.sort(key=lambda p: p.time)
    return pkts


def _syslog(ts: datetime, host: str, pid: int, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} sshd[{pid}]: {msg}"


def build_authlog(rng: random.Random) -> list[str]:
    host = "srv-web"
    lines = [
        _syslog(at(5), host, 801, f"Accepted publickey for rania from {ADMIN_PC} port 50122 ssh2: ED25519 SHA256:q1w2e3r4"),
        # Legitimate typo: one failure then success (must NOT trigger BF-001).
        _syslog(at(13), host, 805, f"Failed password for rania from {ADMIN_PC} port 50188 ssh2"),
        _syslog(at(13) + timedelta(seconds=6), host, 805, f"Accepted password for rania from {ADMIN_PC} port 50188 ssh2"),
        _syslog(at(13) + timedelta(seconds=7), host, 806, "pam_unix(sshd:session): session opened for user rania(uid=1000) by (uid=0)"),
    ]
    # 09:03:10 -> brute force, dictionary on 4 accounts.
    t = at(18) + timedelta(seconds=10)
    users = ["root", "admin", "oracle", "webadmin"]
    pid = 900
    for i in range(24):
        user = users[i % len(users)]
        port = 40000 + i * 7
        if user in ("admin", "oracle"):
            lines.append(_syslog(t, host, pid, f"Invalid user {user} from {ATTACKER} port {port}"))
            lines.append(_syslog(t, host, pid, f"Failed password for invalid user {user} from {ATTACKER} port {port} ssh2"))
        else:
            lines.append(_syslog(t, host, pid, f"Failed password for {user} from {ATTACKER} port {port} ssh2"))
        if i == 11:  # rsyslog duplicate suppression
            lines.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} {host} sshd[{pid}]: message repeated 3 times: "
                         f"[ Failed password for {user} from {ATTACKER} port {port} ssh2]")
        pid += 1
        t += timedelta(seconds=rng.uniform(1.2, 1.8))
    t += timedelta(seconds=8)
    lines.append(_syslog(t, host, pid, f"Accepted password for webadmin from {ATTACKER} port 40999 ssh2"))
    lines.append(_syslog(t, host, pid, "pam_unix(sshd:session): session opened for user webadmin(uid=1001) by (uid=0)"))
    return lines


_EVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _win_event(record_id: int, event_id: int, ts: datetime, data: dict[str, str]) -> str:
    keywords = "0x8010000000000000" if event_id == 4625 else "0x8020000000000000"
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{_EVT_NS}"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>"
        f"<Keywords>{keywords}</Keywords>"
        f'<TimeCreated SystemTime="{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond:06d}0Z"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Correlation/>"
        '<Execution ProcessID="652" ThreadID="4120"/><Channel>Security</Channel>'
        "<Computer>PC-RH-07.entreprise.local</Computer><Security/></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


def build_security_xml(rng: random.Random) -> str:
    events = []
    rid = 81200
    base = {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0"}
    # Legitimate RDP logon by the admin.
    events.append(_win_event(rid, 4624, at(0) + timedelta(seconds=12), {
        **base, "TargetUserName": "rania", "TargetDomainName": "ENTREPRISE", "LogonType": "10",
        "WorkstationName": "ADMIN-PC", "IpAddress": ADMIN_PC, "IpPort": "51022"}))
    rid += 1
    # Local typo at the console (no IP): must be ignored by BF-002.
    events.append(_win_event(rid, 4625, at(10), {
        **base, "TargetUserName": "rh.manager", "TargetDomainName": "ENTREPRISE", "Status": "0xc000006d",
        "SubStatus": "0xc000006a", "LogonType": "2", "WorkstationName": "PC-RH-07", "IpAddress": "-", "IpPort": "-"}))
    rid += 1
    # 09:10 RDP brute force from the compromised srv-web.
    t = at(25)
    users = ["administrateur", "admin", "rh.manager", "support"]
    for i in range(15):
        user = users[i % len(users)]
        sub = "0xc0000064" if user in ("admin", "support") else "0xc000006a"
        events.append(_win_event(rid, 4625, t, {
            **base, "TargetUserName": user, "TargetDomainName": "ENTREPRISE", "Status": "0xc000006d",
            "SubStatus": sub, "LogonType": "10", "WorkstationName": "SRV-WEB", "IpAddress": SRV_WEB, "IpPort": "0"}))
        rid += 1
        t += timedelta(seconds=rng.uniform(1.5, 2.5))
    # Same format as: wevtutil qe Security /f:xml (no root element)
    return "".join(events) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("samples"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    wrpcap(str(args.out / "lab.pcap"), build_pcap(rng))
    (args.out / "auth.log").write_text("\n".join(build_authlog(rng)) + "\n", encoding="utf-8")
    (args.out / "security.xml").write_text(build_security_xml(rng), encoding="utf-8")
    print(f"Jeu de données synthétique écrit dans {args.out}/ : lab.pcap, auth.log, security.xml")


if __name__ == "__main__":
    main()
