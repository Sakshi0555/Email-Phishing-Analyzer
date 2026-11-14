import os

from phishing_analyzer.parser import parse_eml_file
from phishing_analyzer.scoring import score_email

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    return parse_eml_file(os.path.join(FIXTURES, name))


def test_legit_email_scores_low():
    result = score_email(load("legit_email.eml"))
    assert result.score == 0
    assert result.level == "low"
    assert result.reasons == []


def test_phishing_email_scores_high():
    result = score_email(load("phishing_paypal.eml"))
    assert result.level == "high"
    assert result.score >= 60
    reasons_joined = " ".join(result.reasons)
    assert "SPF failed" in reasons_joined
    assert "impersonates brand" in reasons_joined
    assert "resemble brand" in reasons_joined


def test_minimal_email_scores_low_but_not_zero():
    result = score_email(load("minimal_no_received.eml"))
    assert result.level == "low"
    assert 0 < result.score < 30
    reasons_joined = " ".join(result.reasons)
    assert "No Authentication-Results" in reasons_joined
    assert "No Received headers" in reasons_joined
