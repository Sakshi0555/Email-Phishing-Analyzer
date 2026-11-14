"""M6/M7 - Threat intel cache + VirusTotal/URLhaus clients + verdict merge.

Design (per phishing-analyzer-dev-plan.md and the original spec's section 3):
  1. Extract every domain worth checking (sender, reply-to, link domains).
  2. Query VirusTotal first, then URLhaus, for each unique domain.
  3. Cache verdicts in SQLite (domain, source, verdict, checked_at) so
     repeated runs against the same domains don't burn API quota.
  4. A confirmed-malicious verdict from either source overrides the local
     heuristic score and forces it to "high".

Endpoints (verified July 2026):
  - VirusTotal v3 domain report: GET https://www.virustotal.com/api/v3/domains/{domain}
    header "x-apikey"; response .data.attributes.last_analysis_stats has
    malicious/suspicious/harmless/undetected counts.
    Free public tier: 4 req/min, 500 req/day, non-commercial use only.
  - URLhaus host query: POST https://urlhaus-api.abuse.ch/v1/host/
    header "Auth-Key", body {"host": <domain>}; response has query_status
    ("ok" | "no_results" | error string) and, when "ok", a "urls" list
    with per-URL "url_status" ("online" | "offline").

Both clients fail closed: any network error, missing key, or exhausted
rate limit is caught by run_threat_intel() and simply means that source
is skipped for that domain - scoring falls back to the Phase 1 local
heuristics rather than crashing the CLI.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

from phishing_analyzer.datafiles import load_scoring_weights
from phishing_analyzer.parser import ParsedEmail
from phishing_analyzer.scoring import RiskScoreResult, collect_relevant_domains

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


def get_cached_verdict(conn: sqlite3.Connection, domain: str, source: str) -> CachedVerdict | None:
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
        "INSERT INTO domain_verdicts (domain, source, verdict, raw_response, checked_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(domain, source) DO UPDATE SET "
        "verdict=excluded.verdict, raw_response=excluded.raw_response, checked_at=excluded.checked_at",
        (domain.lower(), source, verdict, raw_response, datetime.now(timezone.utc).isoformat()),
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
    """Free public API v3: 4 req/min, 500 req/day, non-commercial use only."""

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
    """Requires a free Auth-Key from auth.abuse.ch (mandatory as of 2026)."""

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
    """4 req/min (in-memory) and 500 req/day (derived from the cache DB,
    so the daily budget persists across separate CLI invocations)."""

    PER_MINUTE = 4
    PER_DAY = 500

    def __init__(self, cache_conn: sqlite3.Connection):
        self._conn = cache_conn
        self._minute_calls: list[datetime] = []

    def _day_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM domain_verdicts WHERE source = ? AND date(checked_at) = date('now')",
            (VirusTotalClient.SOURCE,),
        ).fetchone()
        return row[0] if row else 0

    def allow(self) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)
        self._minute_calls = [t for t in self._minute_calls if t > cutoff]
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
    """Look up one domain against whichever TI sources are configured.

    Cache-first: a verdict checked within CACHE_TTL is reused instead of
    calling the API again. Any failure (network error, missing key, VT
    rate limit exhausted) is swallowed - that source is simply skipped
    for this domain rather than raising out of a CLI run.
    """
    results: list[TILookupResult] = []

    if vt_client and vt_client.api_key:
        cached = get_cached_verdict(cache_conn, domain, VirusTotalClient.SOURCE)
        if cached and _is_fresh(cached.checked_at):
            results.append(TILookupResult(domain, VirusTotalClient.SOURCE, cached.verdict, True))
        elif vt_limiter is None or vt_limiter.allow():
            try:
                verdict, raw = vt_client.lookup_domain(domain)
                store_verdict(
                    cache_conn,
                    domain,
                    VirusTotalClient.SOURCE,
                    verdict,
                    json.dumps(raw) if raw else None,
                )
                if vt_limiter:
                    vt_limiter.record_call()
                results.append(TILookupResult(domain, VirusTotalClient.SOURCE, verdict, False))
            except Exception:
                pass  # network/API failure - fall back to local heuristics for this source

    if urlhaus_client and urlhaus_client.auth_key:
        cached = get_cached_verdict(cache_conn, domain, URLHausClient.SOURCE)
        if cached and _is_fresh(cached.checked_at):
            results.append(TILookupResult(domain, URLHausClient.SOURCE, cached.verdict, True))
        else:
            try:
                verdict, raw = urlhaus_client.lookup_host(domain)
                store_verdict(
                    cache_conn,
                    domain,
                    URLHausClient.SOURCE,
                    verdict,
                    json.dumps(raw) if raw else None,
                )
                results.append(TILookupResult(domain, URLHausClient.SOURCE, verdict, False))
            except Exception:
                pass

    return results


def apply_ti_verdicts(result: RiskScoreResult, ti_results: list[TILookupResult]) -> RiskScoreResult:
    """Fold TI verdicts into an existing RiskScoreResult.

    A confirmed-malicious verdict from either source overrides the local
    heuristic score entirely (score=100, level="high"), per the spec's
    "known-malicious verdict overrides other signals" design. A
    "suspicious" verdict (VirusTotal only) instead adds a configurable
    bump on top of the existing score.
    """
    result.ti_results = ti_results
    malicious_hits = [r for r in ti_results if r.verdict in ("malicious", "malicious_historical")]
    suspicious_hits = [r for r in ti_results if r.verdict == "suspicious"]

    if malicious_hits:
        detail = ", ".join(sorted({f"{r.domain} ({r.source})" for r in malicious_hits}))
        result.score = 100
        result.level = "high"
        result.reasons.append(f"Threat intel confirms malicious: {detail}")
        return result

    if suspicious_hits:
        weights = load_scoring_weights()
        thresholds = weights.get("thresholds", {"medium": 30, "high": 60})
        result.score = min(100, result.score + weights.get("ti_suspicious", 20))
        if result.score >= thresholds.get("high", 60):
            result.level = "high"
        elif result.score >= thresholds.get("medium", 30):
            result.level = "medium"
        detail = ", ".join(sorted({f"{r.domain} ({r.source})" for r in suspicious_hits}))
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
    """Convenience wrapper: check every relevant domain, then merge verdicts."""
    domains = collect_relevant_domains(email, result.link_results)
    ti_results: list[TILookupResult] = []
    for domain in domains:
        ti_results.extend(
            check_domain_ti(domain, cache_conn, vt_client, urlhaus_client, vt_limiter)
        )
    return apply_ti_verdicts(result, ti_results)
