import os
from datetime import datetime, timedelta, timezone

import pytest

from phishing_analyzer import ti
from phishing_analyzer.parser import parse_eml_file
from phishing_analyzer.scoring import RiskScoreResult, score_email

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    return parse_eml_file(os.path.join(FIXTURES, name))


class FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


# --- VirusTotalClient ---


def test_virustotal_client_requires_api_key():
    with pytest.raises(RuntimeError):
        ti.VirusTotalClient(api_key=None).lookup_domain("evil.example")


def test_virustotal_client_parses_malicious_verdict(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        assert url == "https://www.virustotal.com/api/v3/domains/evil.example"
        assert headers == {"x-apikey": "testkey"}
        return FakeResponse(
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 10,
                        }
                    }
                }
            },
        )

    monkeypatch.setattr(ti.requests, "get", fake_get)
    verdict, raw = ti.VirusTotalClient(api_key="testkey").lookup_domain("evil.example")
    assert verdict == "malicious"
    assert raw is not None


def test_virustotal_client_parses_harmless_verdict(monkeypatch):
    monkeypatch.setattr(
        ti.requests,
        "get",
        lambda *a, **k: FakeResponse(
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 70,
                            "undetected": 5,
                        }
                    }
                }
            },
        ),
    )
    verdict, _ = ti.VirusTotalClient(api_key="testkey").lookup_domain("examplecorp.com")
    assert verdict == "harmless"


def test_virustotal_client_404_returns_unknown(monkeypatch):
    monkeypatch.setattr(ti.requests, "get", lambda *a, **k: FakeResponse(404))
    verdict, raw = ti.VirusTotalClient(api_key="testkey").lookup_domain("neverheard.example")
    assert verdict == "unknown"
    assert raw is None


# --- URLHausClient ---


def test_urlhaus_client_requires_auth_key():
    with pytest.raises(RuntimeError):
        ti.URLHausClient(auth_key=None).lookup_host("evil.example")


def test_urlhaus_client_online_url_is_malicious(monkeypatch):
    def fake_post(url, data=None, headers=None, timeout=None):
        assert url == "https://urlhaus-api.abuse.ch/v1/host/"
        assert data == {"host": "evil.example"}
        assert headers == {"Auth-Key": "testauth"}
        return FakeResponse(200, {"query_status": "ok", "urls": [{"url_status": "online"}]})

    monkeypatch.setattr(ti.requests, "post", fake_post)
    verdict, raw = ti.URLHausClient(auth_key="testauth").lookup_host("evil.example")
    assert verdict == "malicious"
    assert raw is not None


def test_urlhaus_client_offline_only_is_malicious_historical(monkeypatch):
    monkeypatch.setattr(
        ti.requests,
        "post",
        lambda *a, **k: FakeResponse(
            200, {"query_status": "ok", "urls": [{"url_status": "offline"}]}
        ),
    )
    verdict, _ = ti.URLHausClient(auth_key="testauth").lookup_host("evil.example")
    assert verdict == "malicious_historical"


def test_urlhaus_client_no_results_is_clean(monkeypatch):
    monkeypatch.setattr(
        ti.requests, "post", lambda *a, **k: FakeResponse(200, {"query_status": "no_results"})
    )
    verdict, _ = ti.URLHausClient(auth_key="testauth").lookup_host("clean.example")
    assert verdict == "clean"


# --- check_domain_ti orchestration (cache-first, rate limiting) ---


class CountingVTClient:
    api_key = "fake"

    def __init__(self, verdict="malicious"):
        self.calls = 0
        self._verdict = verdict

    def lookup_domain(self, domain):
        self.calls += 1
        return self._verdict, {"stub": True}


class AlwaysBlockedLimiter:
    def allow(self):
        return False

    def record_call(self):
        pass


def test_check_domain_ti_reuses_fresh_cache(tmp_path):
    conn = ti.init_cache_db(str(tmp_path / "cache.db"))
    ti.store_verdict(conn, "evil.example", ti.VirusTotalClient.SOURCE, "malicious", "{}")

    client = CountingVTClient()
    results = ti.check_domain_ti("evil.example", conn, vt_client=client)

    assert client.calls == 0
    assert results[0].from_cache is True
    assert results[0].verdict == "malicious"


def test_check_domain_ti_calls_when_cache_stale(tmp_path):
    conn = ti.init_cache_db(str(tmp_path / "cache.db"))
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    conn.execute(
        "INSERT INTO domain_verdicts (domain, source, verdict, raw_response, checked_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("evil.example", ti.VirusTotalClient.SOURCE, "harmless", None, stale_ts),
    )
    conn.commit()

    client = CountingVTClient(verdict="malicious")
    results = ti.check_domain_ti("evil.example", conn, vt_client=client)

    assert client.calls == 1
    assert results[0].verdict == "malicious"
    assert results[0].from_cache is False


def test_check_domain_ti_skips_vt_when_rate_limited(tmp_path):
    conn = ti.init_cache_db(str(tmp_path / "cache.db"))
    client = CountingVTClient()

    results = ti.check_domain_ti(
        "evil.example", conn, vt_client=client, vt_limiter=AlwaysBlockedLimiter()
    )

    assert client.calls == 0
    assert results == []


def test_vt_rate_limiter_blocks_after_minute_budget(tmp_path):
    conn = ti.init_cache_db(str(tmp_path / "cache.db"))
    limiter = ti.VirusTotalRateLimiter(conn)
    for _ in range(ti.VirusTotalRateLimiter.PER_MINUTE):
        assert limiter.allow()
        limiter.record_call()
    assert limiter.allow() is False


# --- apply_ti_verdicts / verdict merge ---


def test_apply_ti_verdicts_malicious_overrides_score():
    result = RiskScoreResult(score=10, level="low", reasons=["minor issue"])
    ti_results = [ti.TILookupResult("evil.example", "virustotal", "malicious", False)]

    updated = ti.apply_ti_verdicts(result, ti_results)

    assert updated.score == 100
    assert updated.level == "high"
    assert "malicious" in " ".join(updated.reasons).lower()


def test_apply_ti_verdicts_suspicious_bumps_score():
    result = RiskScoreResult(score=10, level="low", reasons=[])
    ti_results = [ti.TILookupResult("shady.example", "virustotal", "suspicious", False)]

    updated = ti.apply_ti_verdicts(result, ti_results)

    assert updated.score == 30  # 10 + ti_suspicious weight (20)
    assert updated.level == "medium"


def test_apply_ti_verdicts_clean_does_not_change_score():
    result = RiskScoreResult(score=10, level="low", reasons=[])
    ti_results = [ti.TILookupResult("fine.example", "virustotal", "harmless", False)]

    updated = ti.apply_ti_verdicts(result, ti_results)

    assert updated.score == 10
    assert updated.level == "low"


# --- run_threat_intel end-to-end ---


def test_run_threat_intel_forces_high_on_malicious_link_domain(tmp_path):
    conn = ti.init_cache_db(str(tmp_path / "cache.db"))
    email = load("legit_email.eml")
    base_result = score_email(email)
    assert base_result.level == "low"

    class FakeVT:
        api_key = "fake"

        def lookup_domain(self, domain):
            return "malicious", {"stub": True}

    updated = ti.run_threat_intel(email, base_result, conn, vt_client=FakeVT())

    assert updated.score == 100
    assert updated.level == "high"
    assert any(r.verdict == "malicious" for r in updated.ti_results)
