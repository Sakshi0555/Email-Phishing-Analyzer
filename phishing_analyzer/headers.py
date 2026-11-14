"""M2 - Header anomaly detection.

Works entirely off headers already present in the .eml (this tool never
performs its own DNS/SPF/DKIM re-verification in Phase 1 - see
phishing-analyzer-dev-plan.md for why that's an explicit Phase 1.5
decision, not an oversight).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from phishing_analyzer.datafiles import load_brand_domains
from phishing_analyzer.parser import ParsedEmail

_AUTH_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)
_RECEIVED_FROM_RE = re.compile(
    r"from\s+(?P<host>[^\s(]+)\s*(?:\((?:[^)]*?)?\[?(?P<ip>[0-9a-fA-F:.]+)\]?\))?",
    re.IGNORECASE,
)

_VERDICT_UNKNOWN = "none"


@dataclass
class HeaderAnalysisResult:
    spf: str = _VERDICT_UNKNOWN
    dkim: str = _VERDICT_UNKNOWN
    dmarc: str = _VERDICT_UNKNOWN
    auth_results_present: bool = False

    from_replyto_mismatch: bool = False
    from_domain: str = ""
    reply_to_domains: list[str] = field(default_factory=list)

    display_name_spoof: bool = False
    spoofed_brand: str | None = None

    received_count: int = 0
    received_missing: bool = False
    received_private_ip_spoof: bool = False

    reasons: list[str] = field(default_factory=list)


def analyze_headers(email: ParsedEmail) -> HeaderAnalysisResult:
    result = HeaderAnalysisResult()

    _analyze_auth_results(email, result)
    _analyze_from_replyto(email, result)
    _analyze_display_name_spoof(email, result)
    _analyze_received_chain(email, result)

    return result


def _analyze_auth_results(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    headers = email.auth_results_headers
    result.auth_results_present = bool(headers)

    if not headers:
        result.reasons.append("No Authentication-Results header present (SPF/DKIM/DMARC unknown)")
        return

    # Most recent hop (closest to the recipient) is generally listed first;
    # good enough for a v1 heuristic without cross-checking authserv-id boundaries.
    primary = headers[0]
    verdicts = {m.group(1).lower(): m.group(2).lower() for m in _AUTH_METHOD_RE.finditer(primary)}

    result.spf = verdicts.get("spf", _VERDICT_UNKNOWN)
    result.dkim = verdicts.get("dkim", _VERDICT_UNKNOWN)
    result.dmarc = verdicts.get("dmarc", _VERDICT_UNKNOWN)

    if result.spf == "fail":
        result.reasons.append("SPF check failed")
    if result.dkim == "fail":
        result.reasons.append("DKIM check failed")
    if result.dmarc == "fail":
        result.reasons.append("DMARC check failed")


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _analyze_from_replyto(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    result.from_domain = _domain_of(email.from_addr)
    result.reply_to_domains = [_domain_of(a) for a in email.reply_to_addrs]

    mismatched = [d for d in result.reply_to_domains if d and d != result.from_domain]
    if mismatched:
        result.from_replyto_mismatch = True
        result.reasons.append(
            f"Reply-To domain(s) {mismatched} differ from From domain '{result.from_domain}'"
        )


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _analyze_display_name_spoof(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    if not email.from_display_name:
        return

    display_norm = _normalize(email.from_display_name)
    if not display_norm:
        return

    from_domain = result.from_domain
    for brand_domain in load_brand_domains():
        brand_token = brand_domain.split(".")[0]
        if len(brand_token) < 3:
            continue
        if brand_token in display_norm:
            domain_matches = from_domain == brand_domain or from_domain.endswith("." + brand_domain)
            if not domain_matches:
                result.display_name_spoof = True
                result.spoofed_brand = brand_domain
                result.reasons.append(
                    f"Display name '{email.from_display_name}' references '{brand_token}' "
                    f"but sender domain is '{from_domain}', not '{brand_domain}'"
                )
                break


def _analyze_received_chain(email: ParsedEmail, result: HeaderAnalysisResult) -> None:
    headers = email.received_headers
    result.received_count = len(headers)

    if not headers:
        result.received_missing = True
        result.reasons.append("No Received headers present (unusual for a delivered email)")
        return

    brand_tokens = {d.split(".")[0] for d in load_brand_domains()}

    for header in headers:
        match = _RECEIVED_FROM_RE.search(header)
        if not match:
            continue
        host = (match.group("host") or "").lower()
        ip_text = match.group("ip")
        if not ip_text:
            continue
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if not ip.is_private:
            continue
        host_norm = _normalize(host)
        for brand_token in brand_tokens:
            if len(brand_token) >= 3 and brand_token in host_norm:
                result.received_private_ip_spoof = True
                result.reasons.append(
                    f"Received header claims host '{host}' (references '{brand_token}') "
                    f"but originates from private IP {ip_text}"
                )
                break
        if result.received_private_ip_spoof:
            break
