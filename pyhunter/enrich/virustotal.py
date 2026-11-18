"""VirusTotal API v3 client with throttling, retries, cache and offline mode.

The API key is never stored in the code or the rules: it is read from an
environment variable (``VT_API_KEY`` by default).
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from pyhunter.enrich.cache import Cache

log = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3/"
ENDPOINTS = {"ip": "ip_addresses/{}", "domain": "domains/{}", "hash": "files/{}", "url": "urls/{}"}
GUI = {"ip": "ip-address/{}", "domain": "domain/{}", "hash": "file/{}", "url": "url/{}"}
MALICIOUS_THRESHOLD = 3  # engines flagging "malicious" before we call it malicious

# transport(url, headers, timeout) -> (http_status, json_payload); injectable for tests.
Transport = Callable[[str, dict[str, str], float], tuple[int, dict[str, Any]]]


class TransientError(Exception):
    """Network failure, timeout, HTTP 429 or 5xx: worth retrying."""


def urllib_transport(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 429 or exc.code >= 500:
            raise TransientError(f"HTTP {exc.code}") from exc
        try:
            body = json.loads(exc.read() or b"{}")
        except ValueError:
            body = {}
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransientError(str(exc)) from exc


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VTClient:
    def __init__(
        self,
        api_key: str | None,
        cache: Cache,
        offline: bool = False,
        min_interval: float = 15.0,  # free public API: 4 requests / minute
        timeout: float = 10.0,
        max_retries: int = 3,
        transport: Transport = urllib_transport,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.api_key = api_key
        self.cache = cache
        self.offline = offline
        self.min_interval = min_interval
        self.timeout = timeout
        self.max_retries = max_retries
        self.transport = transport
        self.sleep = sleep
        self.clock = clock
        self._last_request: float | None = None
        self.requests_made = 0

    def lookup(self, ioc_type: str, value: str) -> dict[str, Any]:
        if ioc_type not in ENDPOINTS:
            return {"statut": "ignore", "detail": f"type d'IOC « {ioc_type} » non pris en charge"}

        entry = self.cache.get(ioc_type, value)
        if entry is not None and not entry.stale:
            return self._summarize(ioc_type, value, entry.status, entry.payload, origine="cache", date=entry.fetched_at)

        def stale_or(result: dict[str, Any]) -> dict[str, Any]:
            if entry is not None:  # an old answer is better than none
                return self._summarize(ioc_type, value, entry.status, entry.payload,
                                       origine="cache (expiré)", date=entry.fetched_at)
            return result

        if self.offline:
            return stale_or({"statut": "hors_ligne", "detail": "mode hors ligne : absent du cache"})
        if not self.api_key:
            return stale_or({"statut": "non_configure", "detail": "clé API absente (variable d'environnement)"})

        try:
            status, payload = self._fetch(ioc_type, value)
        except TransientError as exc:
            log.warning("VirusTotal indisponible pour %s %s : %s", ioc_type, value, exc)
            return stale_or({"statut": "erreur", "detail": f"API indisponible après {self.max_retries} tentatives : {exc}"})

        if status in (200, 404):
            self.cache.put(ioc_type, value, status, payload if status == 200 else {})
            fetched = self.cache.get(ioc_type, value)
            return self._summarize(ioc_type, value, status, payload, origine="api",
                                   date=fetched.fetched_at if fetched else None)
        if status in (401, 403):
            return stale_or({"statut": "erreur", "detail": f"clé API refusée (HTTP {status})"})
        return stale_or({"statut": "erreur", "detail": f"réponse inattendue HTTP {status}"})

    def _fetch(self, ioc_type: str, value: str) -> tuple[int, dict[str, Any]]:
        ident = _url_id(value) if ioc_type == "url" else quote(value, safe="")
        url = API_BASE + ENDPOINTS[ioc_type].format(ident)
        headers = {"x-apikey": self.api_key or "", "accept": "application/json"}
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                self.requests_made += 1
                return self.transport(url, headers, self.timeout)
            except TransientError as exc:
                last_error = exc
                if attempt < self.max_retries:
                    backoff = self.min_interval * attempt
                    log.info("tentative %d/%d échouée (%s), nouvel essai dans %.0f s",
                             attempt, self.max_retries, exc, backoff)
                    self.sleep(backoff)
        raise TransientError(str(last_error))

    def _throttle(self) -> None:
        if self._last_request is not None:
            wait = self.min_interval - (self.clock() - self._last_request)
            if wait > 0:
                self.sleep(wait)
        self._last_request = self.clock()

    @staticmethod
    def _summarize(ioc_type: str, value: str, status: int, payload: dict[str, Any], origine: str, date=None) -> dict[str, Any]:
        base = {
            "source": "VirusTotal",
            "origine": origine,
            "date": date.isoformat() if date else None,
            "lien": "https://www.virustotal.com/gui/" + GUI[ioc_type].format(
                _url_id(value) if ioc_type == "url" else value),
        }
        if status == 404:
            return {**base, "statut": "ok", "verdict": "inconnu", "detail": "aucune donnée VirusTotal pour cet IOC"}
        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        if malicious >= MALICIOUS_THRESHOLD:
            verdict = "malveillant"
        elif malicious + suspicious > 0:
            verdict = "suspect"
        else:
            verdict = "non_detecte"
        result = {
            **base, "statut": "ok", "verdict": verdict,
            "malveillant": malicious, "suspect": suspicious,
            "inoffensif": int(stats.get("harmless", 0)), "non_detecte": int(stats.get("undetected", 0)),
            "reputation": attrs.get("reputation"),
        }
        for key, label in (("country", "pays"), ("as_owner", "proprietaire_as"), ("registrar", "registrar")):
            if attrs.get(key):
                result[label] = attrs[key]
        return result
