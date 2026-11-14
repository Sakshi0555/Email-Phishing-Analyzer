"""M6/M7 - Threat intel cache + VirusTotal/URLhaus clients + verdict merge."""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

from phishing_analyzer.datafiles import load_scoring_weights
from phishing_analyzer.parser import ParsedEmail
from phishing_analyzer.scoring import RiskScoreResult, collect_relevant_domains

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_verdicts (
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    raw_response TEXT,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (domain, source)
);
"""

CACHE_TTL = timedelta(hours=24)


@dataclass
class CachedVerdict:
    domain: str
    source: str
    verdict: str
    raw_response: str | None
    checked_at: str


@dataclass
class TILookupResult:
    domain: str
    source: str
    verdict: str
    from_cache: bool = False


def init_cache_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(_SCHEMA)
    conn.commit()
    return conn


def get_cached_verdict(
    conn: sqlite3.Connection,
    domain: str,
    source: str,
) -> CachedVerdict | None:
    row = conn.execute(
        "SELECT domain, source, verdict, raw_response, checked_at "
        "FROM domain_verdicts WHERE domain = ? AND source = ?",
        (domain.lower(), source),
    ).fetchone()

    if row is None:
        return None

    return CachedVerdict(*row)


def store_verdict(
    conn: sqlite3.Connection,
    domain: str,
    source: str,
    verdict: str,
    raw_response: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO domain_verdicts "
        "(domain, source, verdict, raw_response, checked_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(domain, source) DO UPDATE SET "
        "verdict=excluded.verdict, "
        "raw_response=excluded.raw_response, "
        "checked_at=excluded.checked_at",
        (
            domain.lower(),
            source,
            verdict,
            raw_response,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def _is_fresh(checked_at_iso: str) -> bool:
    try:
        checked = datetime.fromisoformat(checked_at_iso)
    except ValueError:
        return False

    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)

    return datetime.now(timezone.utc) - checked < CACHE_TTL


class VirusTotalClient:
    """Free public API v3: 4 req/min, 500 req/day."""

    SOURCE = "virustotal"
    URL_TEMPLATE = "https://www.virustotal.com/api/v3/domains/{domain}"

    def __init__(self, api_key: str | None, timeout: float = 10.0):
        self.api_key = api_key
        self.timeout = timeout

    def lookup_domain(self, domain: str) -> tuple[str, dict | None]:
        if not self.api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not configured")

        response = requests.get(
            self.URL_TEMPLATE.format(domain=domain),
            headers={"x-apikey": self.api_key},
            timeout=self.timeout,
        )

        if response.status_code == 404:
            return "unknown", None

        response.raise_for_status()

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0:
            verdict = "harmless"
        else:
            verdict = "undetected"

        return verdict, data


class URLHausClient:
    """Requires a free Auth-Key from auth.abuse.ch."""

    SOURCE = "urlhaus"
    URL = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self, auth_key: str | None, timeout: float = 10.0):
        self.auth_key = auth_key
        self.timeout = timeout

    def lookup_host(self, domain: str) -> tuple[str, dict | None]:
        if not self.auth_key:
            raise RuntimeError("URLHAUS_AUTH_KEY is not configured")

        response = requests.post(
            self.URL,
            data={"host": domain},
            headers={"Auth-Key": self.auth_key},
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()
        status = data.get("query_status")

        if status == "no_results":
            return "clean", data

        if status != "ok":
            return "unknown", data

        urls = data.get("urls") or []

        if any(u.get("url_status") == "online" for u in urls):
            return "malicious", data

        if urls:
            return "malicious_historical", data

        return "clean", data


class VirusTotalRateLimiter:
    """4 requests/minute and 500 requests/day."""

    PER_MINUTE = 4
    PER_DAY = 500

    def __init__(self, cache_conn: sqlite3.Connection):
        self._conn = cache_conn
        self._minute_calls: list[datetime] = []

    def _day_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM domain_verdicts "
            "WHERE source = ? AND date(checked_at) = date('now')",
            (VirusTotalClient.SOURCE,),
        ).fetchone()

        return row[0] if row else 0

    def allow(self) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)

        self._minute_calls = [timestamp for timestamp in self._minute_calls if timestamp > cutoff]

        if len(self._minute_calls) >= self.PER_MINUTE:
            return False

        return self._day_count() < self.PER_DAY

    def record_call(self) -> None:
        self._minute_calls.append(datetime.now(timezone.utc))


def check_domain_ti(
    domain: str,
    cache_conn: sqlite3.Connection,
    vt_client: VirusTotalClient | None = None,
    urlhaus_client: URLHausClient | None = None,
    vt_limiter: VirusTotalRateLimiter | None = None,
) -> list[TILookupResult]:
    """Look up one domain against configured threat intelligence sources.

    Cached results are reused for 24 hours. Network failures are logged
    and skipped so local phishing detection can continue.
    """

    results: list[TILookupResult] = []

    # VirusTotal lookup
    if vt_client and vt_client.api_key:
        cached = get_cached_verdict(
            cache_conn,
            domain,
            VirusTotalClient.SOURCE,
        )

        if cached and _is_fresh(cached.checked_at):
            results.append(
                TILookupResult(
                    domain,
                    VirusTotalClient.SOURCE,
                    cached.verdict,
                    True,
                )
            )

        elif vt_limiter is None or vt_limiter.allow():
            try:
                verdict, raw = vt_client.lookup_domain(domain)

            except (requests.RequestException, ValueError) as exc:
                logger.warning(
                    "VirusTotal lookup failed for %s: %s",
                    domain,
                    exc,
                )

            else:
                store_verdict(
                    cache_conn,
                    domain,
                    VirusTotalClient.SOURCE,
                    verdict,
                    json.dumps(raw) if raw else None,
                )

                if vt_limiter:
                    vt_limiter.record_call()

                results.append(
                    TILookupResult(
                        domain,
                        VirusTotalClient.SOURCE,
                        verdict,
                        False,
                    )
                )

    # URLhaus lookup
    if urlhaus_client and urlhaus_client.auth_key:
        cached = get_cached_verdict(
            cache_conn,
            domain,
            URLHausClient.SOURCE,
        )

        if cached and _is_fresh(cached.checked_at):
            results.append(
                TILookupResult(
                    domain,
                    URLHausClient.SOURCE,
                    cached.verdict,
                    True,
                )
            )

        else:
            try:
                verdict, raw = urlhaus_client.lookup_host(domain)

            except (requests.RequestException, ValueError) as exc:
                logger.warning(
                    "URLhaus lookup failed for %s: %s",
                    domain,
                    exc,
                )

            else:
                store_verdict(
                    cache_conn,
                    domain,
                    URLHausClient.SOURCE,
                    verdict,
                    json.dumps(raw) if raw else None,
                )

                results.append(
                    TILookupResult(
                        domain,
                        URLHausClient.SOURCE,
                        verdict,
                        False,
                    )
                )

    return results


def apply_ti_verdicts(
    result: RiskScoreResult,
    ti_results: list[TILookupResult],
) -> RiskScoreResult:
    """Merge threat intelligence verdicts into the existing risk score."""

    result.ti_results = ti_results

    malicious_hits = [
        item for item in ti_results if item.verdict in ("malicious", "malicious_historical")
    ]

    suspicious_hits = [item for item in ti_results if item.verdict == "suspicious"]

    if malicious_hits:
        detail = ", ".join(sorted({f"{item.domain} ({item.source})" for item in malicious_hits}))

        result.score = 100
        result.level = "high"
        result.reasons.append(f"Threat intel confirms malicious: {detail}")

        return result

    if suspicious_hits:
        weights = load_scoring_weights()

        thresholds = weights.get(
            "thresholds",
            {"medium": 30, "high": 60},
        )

        result.score = min(
            100,
            result.score + weights.get("ti_suspicious", 20),
        )

        if result.score >= thresholds.get("high", 60):
            result.level = "high"

        elif result.score >= thresholds.get("medium", 30):
            result.level = "medium"

        detail = ", ".join(sorted({f"{item.domain} ({item.source})" for item in suspicious_hits}))

        result.reasons.append(f"Threat intel flags as suspicious: {detail}")

    return result


def run_threat_intel(
    email: ParsedEmail,
    result: RiskScoreResult,
    cache_conn: sqlite3.Connection,
    vt_client: VirusTotalClient | None = None,
    urlhaus_client: URLHausClient | None = None,
    vt_limiter: VirusTotalRateLimiter | None = None,
) -> RiskScoreResult:
    """Check every relevant domain and merge threat intelligence results."""

    domains = collect_relevant_domains(email, result.link_results)

    ti_results: list[TILookupResult] = []

    for domain in domains:
        ti_results.extend(
            check_domain_ti(
                domain,
                cache_conn,
                vt_client,
                urlhaus_client,
                vt_limiter,
            )
        )

    return apply_ti_verdicts(result, ti_results)
