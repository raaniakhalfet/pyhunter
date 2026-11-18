"""Configuration: defaults, optionally overridden by a YAML file (pyhunter.yaml)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "regles": ["rules"],
    "virustotal": {
        "cle_api_env": "VT_API_KEY",  # name of the environment variable, never the key itself
        "cache": ".pyhunter/cache.sqlite",
        "ttl": "7d",
        "intervalle_min": "15s",  # free public API: 4 requests / minute
        "timeout": "10s",
        "tentatives": 3,
        "enrichir_ip_privees": False,
    },
    "syslog": {
        "annee": None,  # syslog lines have no year: current year if null
        "fuseau": "UTC",  # time zone of the analysed machine, e.g. Africa/Tunis
    },
    "correlation": {
        "horizon_succes": "30m",  # success after brute force searched up to this delay
    },
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)
    candidate = Path(path) if path else Path("pyhunter.yaml")
    if path and not candidate.is_file():
        raise FileNotFoundError(f"fichier de configuration introuvable : {candidate}")
    if candidate.is_file():
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{candidate} : la configuration doit être un dictionnaire YAML")
        if "cle_api" in (data.get("virustotal") or {}):
            raise ValueError(
                f"{candidate} : ne mettez pas la clé API dans le fichier ; "
                "utilisez la variable d'environnement définie par virustotal.cle_api_env"
            )
        _merge(config, data)
    return config
