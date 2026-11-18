from datetime import timedelta, timezone

import pytest

from pyhunter.utils import (is_public_ip, is_reserved_domain, parse_duration, parse_iso_ts,
                            shannon_entropy, split_domain)


def test_entropy_bounds():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abcdefgh") == pytest.approx(3.0)


def test_entropy_separates_random_from_words():
    assert shannon_entropy("www") < 2
    assert shannon_entropy("mail") < 2.5
    assert shannon_entropy("26k6qcdctricbjjugyiximlkhsimqtgh") > 3.5


@pytest.mark.parametrize("name, expected", [
    ("evil.com", ("", "evil.com")),
    ("a.b.evil.com.", ("a.b", "evil.com")),
    ("www.tek-up.com.tn", ("www", "tek-up.com.tn")),
    ("x.y.z.exfil-lab.test", ("x.y.z", "exfil-lab.test")),
])
def test_split_domain(name, expected):
    assert split_domain(name) == expected


@pytest.mark.parametrize("text, seconds", [("60s", 60), ("5m", 300), ("1h", 3600), ("500ms", 0.5), (30, 30), ("2d", 172800)])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == timedelta(seconds=seconds)


@pytest.mark.parametrize("bad", ["", "abc", "10 minutes", "-5s", True])
def test_parse_duration_rejects(bad):
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_ip_and_domain_classification():
    assert not is_public_ip("192.168.56.10")
    assert not is_public_ip("203.0.113.5")  # TEST-NET-3, documentation range
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("not-an-ip")
    assert is_reserved_domain("exfil-lab.test")
    assert not is_reserved_domain("evil.com")


@pytest.mark.parametrize("raw", [
    "2026-11-20T09:10:00.1234567Z",      # Windows XML, 7 digits
    "2026-11-20 09:10:00.123456+00:00",  # python-evtx
    "2026-11-20T10:10:00.123456+01:00",  # offset
])
def test_parse_iso_ts_variants(raw):
    ts = parse_iso_ts(raw)
    assert ts.tzinfo == timezone.utc
    assert (ts.hour, ts.minute, ts.microsecond) == (9, 10, 123456)


def test_timezone_loading_without_tz_database():
    from pyhunter.pipeline import load_timezone
    assert load_timezone("UTC") is timezone.utc  # never needs tzdata (Windows)
    assert load_timezone(None) is timezone.utc
    with pytest.raises(ValueError, match="tzdata"):
        load_timezone("Mars/Olympus_Mons")
