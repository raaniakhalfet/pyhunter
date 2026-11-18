from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from pyhunter.ingest import iter_authlog, iter_pcap, iter_windows_events
from pyhunter.ingest.evtx import parse_record_xml

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------- auth.log ----------

def test_authlog_failed_and_accepted(tmp_path):
    log = write(tmp_path, "auth.log", "\n".join([
        "Nov 20 09:03:10 srv sshd[900]: Failed password for root from 10.0.0.5 port 40000 ssh2",
        "Nov 20 09:03:11 srv sshd[901]: Invalid user oracle from 10.0.0.5 port 40001",
        "Nov 20 09:03:11 srv sshd[901]: Failed password for invalid user oracle from 10.0.0.5 port 40001 ssh2",
        "Nov 20 09:03:12 srv sshd[902]: pam_unix(sshd:auth): authentication failure; rhost=10.0.0.5 user=root",
        "Nov 20 09:03:20 srv sshd[903]: Accepted password for webadmin from 10.0.0.5 port 40100 ssh2",
        "Nov 20 09:03:21 srv CRON[1]: pam_unix(cron:session): session opened for user root",
    ]))
    events = list(iter_authlog(log, year=2026))
    kinds = [e.kind for e in events]
    # "Invalid user" and pam_unix lines are not counted twice
    assert kinds == ["auth_failure", "auth_failure", "auth_success"]
    assert events[1].user == "oracle" and events[1].extra["utilisateur_invalide"] is True
    assert events[0].src_ip == "10.0.0.5" and events[0].src_port == 40000
    assert events[0].ts == datetime(2026, 11, 20, 9, 3, 10, tzinfo=timezone.utc)
    assert events[2].user == "webadmin"


def test_authlog_message_repeated_expands(tmp_path):
    log = write(tmp_path, "auth.log",
                "Nov 20 09:03:10 srv sshd[900]: message repeated 3 times: [ Failed password for root from 10.0.0.5 port 4 ssh2]\n")
    assert len(list(iter_authlog(log, year=2026))) == 3


def test_authlog_timezone_and_rfc3339(tmp_path):
    log = write(tmp_path, "auth.log", "\n".join([
        "Nov 20 10:00:00 srv sshd[1]: Failed password for root from 10.0.0.5 port 1 ssh2",
        "2026-11-20T10:00:05.250+01:00 srv sshd-session[2]: Failed password for root from 10.0.0.5 port 2 ssh2",
    ]))
    first, second = iter_authlog(log, year=2026, tz=ZoneInfo("Africa/Tunis"))  # UTC+1
    assert first.ts.hour == 9
    assert (second.ts.hour, second.ts.second) == (9, 5)


def test_authlog_year_rollover(tmp_path):
    log = write(tmp_path, "auth.log", "\n".join([
        "Dec 31 23:59:59 srv sshd[1]: Failed password for root from 10.0.0.5 port 1 ssh2",
        "Jan  1 00:00:01 srv sshd[2]: Failed password for root from 10.0.0.5 port 2 ssh2",
    ]))
    a, b = iter_authlog(log, year=2026)
    assert (a.ts.year, b.ts.year) == (2026, 2027)


def test_authlog_ignores_garbage(tmp_path):
    stats = {}
    log = write(tmp_path, "auth.log", "not a syslog line\n\n")
    assert list(iter_authlog(log, year=2026, stats=stats)) == []
    assert stats["lignes_ignorees"] == 1


# ---------- Windows events ----------

def win_xml(event_id=4625, ip="192.168.56.20", logon_type="10", user="admin", sub="0xc000006a"):
    return (
        f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID>'
        '<TimeCreated SystemTime="2026-11-20T09:10:00.1234567Z"/><Computer>PC-RH-07</Computer></System>'
        f'<EventData><Data Name="TargetUserName">{user}</Data><Data Name="TargetDomainName">CORP</Data>'
        f'<Data Name="SubStatus">{sub}</Data><Data Name="LogonType">{logon_type}</Data>'
        f'<Data Name="IpAddress">{ip}</Data><Data Name="IpPort">0</Data></EventData></Event>'
    )


def test_parse_4625_rdp():
    e = parse_record_xml(win_xml())
    assert (e.kind, e.service, e.src_ip, e.user) == ("auth_failure", "rdp", "192.168.56.20", "admin")
    assert e.extra["raison"] == "mot de passe incorrect"
    assert e.src_port is None  # IpPort 0 = unknown


def test_parse_local_logon_has_no_ip():
    e = parse_record_xml(win_xml(ip="-", logon_type="2"))
    assert e.src_ip is None and e.service == "interactif"


def test_parse_other_event_ids_ignored():
    assert parse_record_xml(win_xml(event_id=4672)) is None


def test_wevtutil_export_without_root(tmp_path):
    path = write(tmp_path, "sec.xml", win_xml() + win_xml(event_id=4624, user="rania") + "\n")
    events = list(iter_windows_events(path))
    assert [e.kind for e in events] == ["auth_failure", "auth_success"]


# ---------- PCAP ----------

def test_pcap_extracts_syn_synack_dns(tmp_path):
    def p(layer, t):
        pkt = Ether() / layer
        pkt.time = t
        return pkt
    t = datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc).timestamp()
    pkts = [
        p(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5555, dport=22, flags="S"), t),
        p(IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=22, dport=5555, flags="SA"), t + 0.001),
        p(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5555, dport=22, flags="A"), t + 0.002),  # ignored
        p(IP(src="10.0.0.9", dst="10.0.0.2") / UDP(sport=3333, dport=53) / DNS(rd=1, qd=DNSQR(qname="abc.evil.com")), t + 1),
        p(IP(src="10.0.0.2", dst="10.0.0.9") / UDP(sport=53, dport=3333) / DNS(qr=1, qd=DNSQR(qname="abc.evil.com")), t + 1.1),
    ]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts)
    stats = {}
    events = list(iter_pcap(path, stats=stats))
    assert stats["paquets"] == 5
    assert [e.kind for e in events] == ["tcp_syn", "tcp_synack", "dns_query"]  # DNS responses ignored
    dns = events[2]
    assert (dns.query, dns.base_domain, dns.extra["sous_domaine"]) == ("abc.evil.com", "evil.com", "abc")
    assert events[0].ts.tzinfo == timezone.utc
