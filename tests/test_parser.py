import os

from phishing_analyzer.parser import parse_eml_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    return parse_eml_file(os.path.join(FIXTURES, name))


def test_legit_email_basic_fields():
    email = load("legit_email.eml")
    assert email.from_addr == "billing@examplecorp.com"
    assert email.from_display_name == "ExampleCorp Billing"
    assert email.reply_to_addrs == ["billing@examplecorp.com"]
    assert email.to_addrs == ["user@example.com"]
    assert email.subject == "Your March invoice is ready"
    assert "invoice is ready" in email.body_text
    assert "<a href" in email.body_html
    assert len(email.received_headers) == 2
    assert len(email.auth_results_headers) == 1


def test_phishing_email_basic_fields():
    email = load("phishing_paypal.eml")
    assert email.from_addr == "security@paypa1-support.com"
    assert email.from_display_name == "PayPal Security"
    assert email.reply_to_addrs == ["replies@totally-different-domain.ru"]
    assert "bit.ly" in email.body_text
    assert "203.0.113.5" in email.body_html


def test_minimal_email_no_received_headers():
    email = load("minimal_no_received.eml")
    assert email.received_headers == []
    assert email.auth_results_headers == []
    assert email.body_text.strip().startswith("A password reset")


def test_attachments_default_empty_for_simple_messages():
    email = load("minimal_no_received.eml")
    assert email.attachments == []
