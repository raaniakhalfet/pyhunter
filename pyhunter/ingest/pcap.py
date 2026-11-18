"""PCAP / PCAPNG reader based on scapy.

Only the packets useful to the detections are turned into events:
  * TCP SYN without ACK  -> ``tcp_syn``     (connection attempt / scan probe)
  * TCP SYN+ACK          -> ``tcp_synack``  (port answered: open)
  * DNS query (qr = 0)   -> ``dns_query``
Everything else is counted but not kept, so large captures stay cheap.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from pyhunter.models import Event
from pyhunter.utils import split_domain

log = logging.getLogger(__name__)

SYN = 0x02
ACK = 0x10


def iter_pcap(path: str | Path, stats: dict | None = None) -> Iterator[Event]:
    # Imported lazily: scapy is slow to import and not needed for log-only runs.
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    stats = stats if stats is not None else {}
    stats.setdefault("paquets", 0)
    reader = PcapReader(str(path))  # detects pcap vs pcapng from the magic number
    try:
        for pkt in reader:
            stats["paquets"] += 1
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)

            if TCP in pkt:
                tcp = pkt[TCP]
                flags = int(tcp.flags)
                if flags & SYN:
                    kind = "tcp_synack" if flags & ACK else "tcp_syn"
                    yield Event(
                        ts=ts, source="pcap", kind=kind,
                        src_ip=src, dst_ip=dst,
                        src_port=int(tcp.sport), dst_port=int(tcp.dport),
                        raw=pkt.summary(),
                    )
                    continue

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and int(pkt[DNS].qr) == 0:
                qname = pkt[DNSQR].qname
                name = (qname.decode("utf-8", errors="replace") if isinstance(qname, bytes) else str(qname)).rstrip(".")
                if not name:
                    continue
                sub, base = split_domain(name)
                sport = getattr(pkt[DNS].underlayer, "sport", None)
                dport = getattr(pkt[DNS].underlayer, "dport", None)
                yield Event(
                    ts=ts, source="pcap", kind="dns_query",
                    src_ip=src, dst_ip=dst,
                    src_port=int(sport) if sport is not None else None,
                    dst_port=int(dport) if dport is not None else None,
                    query=name, base_domain=base,
                    raw=pkt.summary(),
                    extra={"sous_domaine": sub, "qtype": int(pkt[DNSQR].qtype)},
                )
    finally:
        reader.close()
    log.info("%s : %d paquets lus", path, stats["paquets"])
