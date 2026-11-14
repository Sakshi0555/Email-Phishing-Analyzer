"""Cache primitive tests. Client + orchestration tests live in test_ti.py
(this file kept separately named since it predates the Phase 2 client
implementation and still covers just the raw cache read/write path)."""

from phishing_analyzer.ti import (
    URLHausClient,
    VirusTotalClient,
    get_cached_verdict,
    init_cache_db,
    store_verdict,
)


def test_cache_round_trip(tmp_path):
    db_path = tmp_path / "ti_cache.sqlite3"
    conn = init_cache_db(str(db_path))

    assert get_cached_verdict(conn, "evil.example", "virustotal") is None

    store_verdict(conn, "evil.example", "virustotal", "malicious", raw_response="{}")
    cached = get_cached_verdict(conn, "evil.example", "virustotal")

    assert cached is not None
    assert cached.domain == "evil.example"
    assert cached.verdict == "malicious"


def test_clients_require_credentials():
    import pytest

    with pytest.raises(RuntimeError):
        VirusTotalClient(api_key=None).lookup_domain("evil.example")
    with pytest.raises(RuntimeError):
        URLHausClient(auth_key=None).lookup_host("evil.example")
