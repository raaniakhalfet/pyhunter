"""Input parsers. Each one yields normalised ``Event`` objects."""

from pyhunter.ingest.authlog import iter_authlog
from pyhunter.ingest.evtx import iter_windows_events
from pyhunter.ingest.pcap import iter_pcap

__all__ = ["iter_authlog", "iter_pcap", "iter_windows_events"]
