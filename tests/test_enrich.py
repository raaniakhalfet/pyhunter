from datetime import datetime, timedelta, timezone

import pytest

from pyhunter.enrich import Cache, VTClient, enrich_iocs
from pyhunter.enrich.virustotal import TransientError

MALICIOUS = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 20},
                                     "reputation": -40, "country": "NL", "as_owner": "Example AS"}}}


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def cache():
    c = Cache(":memory:", ttl=timedelta(days=7))
    yield c
    c.close()


def client(cache, transport, **kw):
    return VTClient("secret-key", cache, transport=transport, sleep=lambda s: None, **kw)


def test_lookup_then_cache_hit(cache):
    transport = FakeTransport([(200, MALICIOUS)])
    vt = client(cache, transport)
    first = vt.lookup("ip", "45.33.32.156")
    second = vt.lookup("ip", "45.33.32.156")
    assert first["verdict"] == "malveillant" and first["origine"] == "api" and first["malveillant"] == 12
    assert second["origine"] == "cache"
    assert len(transport.calls) == 1  # second answer served from cache
    url, headers = transport.calls[0]
    assert url.endswith("/ip_addresses/45.33.32.156") and headers["x-apikey"] == "secret-key"


def test_not_found_is_cached_as_unknown(cache):
    transport = FakeTransport([(404, {})])
    vt = client(cache, transport)
    assert vt.lookup("domain", "never-seen.example.org")["verdict"] == "inconnu"
    assert vt.lookup("domain", "never-seen.example.org")["origine"] == "cache"


def test_offline_uses_cache_only(cache):
    cache.put("ip", "8.8.8.8", 200, MALICIOUS)
    transport = FakeTransport([])
    vt = client(cache, transport, offline=True)
    assert vt.lookup("ip", "8.8.8.8")["verdict"] == "malveillant"
    assert vt.lookup("ip", "1.1.1.1")["statut"] == "hors_ligne"
    assert transport.calls == []


def test_stale_entry_refreshed_online_and_used_offline(cache):
    old = datetime.now(timezone.utc) - timedelta(days=30)
    cache.put("ip", "8.8.8.8", 200, MALICIOUS, now=old)
    assert client(cache, FakeTransport([]), offline=True).lookup("ip", "8.8.8.8")["origine"] == "cache (expiré)"
    transport = FakeTransport([(200, {"data": {"attributes": {"last_analysis_stats": {}}}})])
    fresh = client(cache, transport).lookup("ip", "8.8.8.8")
    assert fresh["origine"] == "api" and fresh["verdict"] == "non_detecte"


def test_retry_then_success(cache):
    transport = FakeTransport([TransientError("HTTP 429"), (200, MALICIOUS)])
    assert client(cache, transport).lookup("ip", "8.8.4.4")["verdict"] == "malveillant"
    assert len(transport.calls) == 2


def test_api_down_returns_error_without_crashing(cache):
    transport = FakeTransport([TransientError("timeout")] * 3)
    result = client(cache, transport, max_retries=3).lookup("ip", "8.8.4.4")
    assert result["statut"] == "erreur" and len(transport.calls) == 3


def test_missing_key(cache):
    vt = VTClient(None, cache, transport=FakeTransport([]))
    assert vt.lookup("ip", "8.8.8.8")["statut"] == "non_configure"


def test_throttling_waits_between_requests(cache):
    waits, now = [], [100.0]
    transport = FakeTransport([(200, MALICIOUS), (200, MALICIOUS)])
    vt = VTClient("k", cache, transport=transport, min_interval=15, sleep=waits.append, clock=lambda: now[0])
    vt.lookup("ip", "8.8.8.8")
    now[0] += 2
    vt.lookup("ip", "9.9.9.9")
    assert waits == [pytest.approx(13)]


def test_private_ips_and_reserved_domains_are_not_sent(cache):
    transport = FakeTransport([(200, MALICIOUS)])
    iocs = {("ip", "192.168.56.10"): ["A"], ("domain", "exfil-lab.test"): ["B"], ("ip", "45.33.32.156"): ["C"]}
    results = enrich_iocs(iocs, client(cache, transport))
    assert results[("ip", "192.168.56.10")]["statut"] == "ignore"
    assert results[("domain", "exfil-lab.test")]["statut"] == "ignore"
    assert results[("ip", "45.33.32.156")]["verdict"] == "malveillant"
    assert len(transport.calls) == 1
