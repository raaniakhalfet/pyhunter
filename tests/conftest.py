import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyhunter.models import Event  # noqa: E402

RULES_DIR = ROOT / "rules"
T0 = datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc)


def ev(seconds: float = 0, kind: str = "auth_failure", source: str = "auth.log", **kw) -> Event:
    """Build an event T0 + seconds."""
    if kind.startswith("auth"):
        kw.setdefault("service", "ssh")
    return Event(ts=T0 + timedelta(seconds=seconds), source=source, kind=kind, **kw)


@pytest.fixture(scope="session")
def lab_data(tmp_path_factory):
    """The synthetic scenario produced by scripts/generate_lab_data.py."""
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "generate_lab_data.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    out = tmp_path_factory.mktemp("lab")
    import random
    from scapy.utils import wrpcap
    rng = random.Random(42)
    wrpcap(str(out / "lab.pcap"), gen.build_pcap(rng))
    (out / "auth.log").write_text("\n".join(gen.build_authlog(rng)) + "\n", encoding="utf-8")
    (out / "security.xml").write_text(gen.build_security_xml(rng), encoding="utf-8")
    return out
