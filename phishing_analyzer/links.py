"""M3 - Suspicious link and domain extraction.

Pulls URLs out of both the plaintext and HTML bodies and flags:
  - URL-shortener domains
  - IP-literal links (http://203.0.113.5/...)
  - anchor text that looks like one domain while the real href points
    somewhere else (the classic "looks like paypal.com" trick)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishing_analyzer.datafiles import load_shortener_domains
from phishing_analyzer.parser import ParsedEmail

# Deliberately conservative plaintext URL matcher - good enough for email bodies.
_PLAINTEXT_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)

# Matches a bare domain-looking token inside anchor text, e.g. "www.paypal.com" or "paypal.com/login"
_ANCHOR_DOMAIN_RE = re.compile(r"(?:https?://)?(?P<host>(?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)


@dataclass
class LinkInfo:
    href: str
    anchor_text: str
    source: str  # "html" or "text"
    domain: str
    is_ip_literal: bool
    is_shortener: bool
    anchor_href_mismatch: bool
    mismatch_detail: str | None = None


class _AnchorExtractor(HTMLParser):
    """Collects (href, anchor_text) pairs from <a> tags."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None
            self._current_text = []


def _domain_of_url(url: str) -> str:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return (host or "").lower()


def _is_ip_literal(domain: str) -> bool:
    if not domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def extract_links(email: ParsedEmail) -> list[LinkInfo]:
    shorteners = load_shortener_domains()
    results: list[LinkInfo] = []

    # --- HTML anchors: href vs. displayed anchor text ---
    if email.body_html:
        parser = _AnchorExtractor()
        try:
            parser.feed(email.body_html)
        except (ValueError, TypeError):
            pass
        for href, anchor_text in parser.links:
            domain = _domain_of_url(href)
            mismatch, detail = _check_anchor_mismatch(href, domain, anchor_text)
            results.append(
                LinkInfo(
                    href=href,
                    anchor_text=anchor_text,
                    source="html",
                    domain=domain,
                    is_ip_literal=_is_ip_literal(domain),
                    is_shortener=domain in shorteners,
                    anchor_href_mismatch=mismatch,
                    mismatch_detail=detail,
                )
            )

    # --- Plaintext URLs ---
    if email.body_text:
        for match in _PLAINTEXT_URL_RE.finditer(email.body_text):
            href = match.group(0).rstrip(".,;:!?")
            domain = _domain_of_url(href)
            results.append(
                LinkInfo(
                    href=href,
                    anchor_text="",
                    source="text",
                    domain=domain,
                    is_ip_literal=_is_ip_literal(domain),
                    is_shortener=domain in shorteners,
                    anchor_href_mismatch=False,
                )
            )

    return results


def _check_anchor_mismatch(
    href: str, href_domain: str, anchor_text: str
) -> tuple[bool, str | None]:
    if not anchor_text or not href_domain:
        return False, None

    match = _ANCHOR_DOMAIN_RE.search(anchor_text)
    if not match:
        return False, None

    anchor_domain = match.group("host").lower()
    if anchor_domain == href_domain:
        return False, None
    if href_domain.endswith("." + anchor_domain) or anchor_domain.endswith("." + href_domain):
        return False, None

    return True, f"Anchor text references '{anchor_domain}' but href points to '{href_domain}'"
