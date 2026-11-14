import os

from phishing_analyzer.headers import analyze_headers
from phishing_analyzer.parser import parse_eml_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    return parse_eml_file(os.path.join(FIXTURES, name))


def test_legit_email_passes_auth_and_has_no_anomalies():
    result = analyze_headers(load("legit_email.eml"))
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.from_replyto_mismatch is False
    assert result.display_name_spoof is False
    assert result.received_missing is False
    assert result.received_count == 2


def test_phishing_email_fails_auth_and_flags_spoof():
    result = analyze_headers(load("phishing_paypal.eml"))
    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"
    assert result.from_replyto_mismatch is True
    assert "totally-different-domain.ru" in result.reply_to_domains
    assert result.display_name_spoof is True
    assert result.spoofed_brand == "paypal.com"
    assert result.received_missing is True
    assert len(result.reasons) >= 4


def test_minimal_email_flags_missing_auth_and_received():
    result = analyze_headers(load("minimal_no_received.eml"))
    assert result.auth_results_present is False
    assert result.spf == "none"
    assert result.dkim == "none"
    assert result.dmarc == "none"
    assert result.received_missing is True
    assert result.display_name_spoof is False
