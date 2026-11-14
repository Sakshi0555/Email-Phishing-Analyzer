import os

from phishing_analyzer.links import extract_links
from phishing_analyzer.parser import parse_eml_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    return parse_eml_file(os.path.join(FIXTURES, name))


def test_legit_email_links_are_clean():
    links = extract_links(load("legit_email.eml"))
    assert len(links) >= 1
    for link in links:
        assert link.is_ip_literal is False
        assert link.is_shortener is False
        assert link.anchor_href_mismatch is False


def test_phishing_email_flags_ip_literal_and_anchor_mismatch():
    links = extract_links(load("phishing_paypal.eml"))
    html_links = [link for link in links if link.source == "html"]

    ip_link = next(link for link in html_links if link.is_ip_literal)
    assert ip_link.domain == "203.0.113.5"
    assert ip_link.anchor_href_mismatch is True
    assert "paypal.com" in ip_link.mismatch_detail

    shortener_links = [link for link in links if link.is_shortener]
    assert any(link.domain == "bit.ly" for link in shortener_links)


def test_plaintext_urls_are_captured_too():
    links = extract_links(load("phishing_paypal.eml"))
    text_links = [link for link in links if link.source == "text"]
    assert any(link.domain == "203.0.113.5" for link in text_links)
    assert any(link.domain == "bit.ly" for link in text_links)
