"""M5 - Composite weighted risk score.

Combines header anomaly signals (M2), link signals (M3), and lookalike
domain signals (M4) into a single 0-100 score plus a low/medium/high
level. Each signal category contributes its configured weight at most
once (so, e.g., ten IP-literal links don't blow the score past what one
would), keeping the score bounded and the reasons list readable.

Weights live in data/scoring_weights.json so they can be tuned without
touching code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_analyzer.datafiles import load_scoring_weights
from phishing_analyzer.domains import DomainMatch, check_lookalike_domains
from phishing_analyzer.headers import HeaderAnalysisResult, analyze_headers
from phishing_analyzer.links import LinkInfo, extract_links
from phishing_analyzer.parser import ParsedEmail


@dataclass
class RiskScoreResult:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)

    header_result: HeaderAnalysisResult | None = None
    link_results: list[LinkInfo] = field(default_factory=list)
    domain_matches: list[DomainMatch] = field(default_factory=list)
    ti_results: list = field(default_factory=list)  # populated by ti.run_threat_intel (Phase 2)


def collect_relevant_domains(email: ParsedEmail, links: list[LinkInfo]) -> list[str]:
    """Every domain worth checking - sender, reply-to, and link domains.

    Public (not just used internally by score_email) because ti.py's
    Phase 2 orchestration needs the same domain set to run VirusTotal/
    URLhaus lookups against.
    """
    domains = {email.header("From") and email.from_addr.rsplit("@", 1)[-1]}
    domains.update(addr.rsplit("@", 1)[-1] for addr in email.reply_to_addrs if "@" in addr)
    domains.update(link.domain for link in links if link.domain)
    return [d for d in domains if d]


def score_email(email: ParsedEmail, weights: dict | None = None) -> RiskScoreResult:
    weights = weights if weights is not None else load_scoring_weights()
    thresholds = weights.get("thresholds", {"medium": 30, "high": 60})

    header_result = analyze_headers(email)
    link_results = extract_links(email)
    domain_matches = check_lookalike_domains(collect_relevant_domains(email, link_results))

    score = 0
    reasons: list[str] = []

    def add(condition: bool, weight_key: str, reason: str | None = None) -> None:
        nonlocal score
        if condition:
            score += weights.get(weight_key, 0)
            if reason:
                reasons.append(reason)

    add(header_result.spf == "fail", "spf_fail", "SPF failed")
    add(header_result.dkim == "fail", "dkim_fail", "DKIM failed")
    add(header_result.dmarc == "fail", "dmarc_fail", "DMARC failed")
    add(
        not header_result.auth_results_present,
        "auth_missing",
        "No Authentication-Results header present",
    )
    add(
        header_result.from_replyto_mismatch,
        "from_replyto_mismatch",
        "From / Reply-To domain mismatch",
    )
    add(
        header_result.display_name_spoof,
        "display_name_spoof",
        f"Display name impersonates brand '{header_result.spoofed_brand}'",
    )
    add(header_result.received_missing, "received_missing", "No Received headers present")
    add(
        header_result.received_private_ip_spoof,
        "received_anomaly",
        "Received header claims a brand hostname from a private IP",
    )

    any_ip_literal = any(link.is_ip_literal for link in link_results)
    any_shortener = any(link.is_shortener for link in link_results)
    any_anchor_mismatch = any(link.anchor_href_mismatch for link in link_results)

    add(any_ip_literal, "ip_literal_link", "Link points directly to an IP address")
    add(any_shortener, "shortener_link", "Link uses a URL-shortening service")
    add(
        any_anchor_mismatch,
        "anchor_href_mismatch",
        "Anchor text domain does not match the actual link destination",
    )

    any_lookalike = any(m.match_type in ("typosquat", "combosquat") for m in domain_matches)
    any_homograph = any(m.match_type == "homograph" for m in domain_matches)

    if any_lookalike:
        lookalike_brands = sorted(
            {m.matched_brand for m in domain_matches if m.match_type in ("typosquat", "combosquat")}
        )
        add(True, "lookalike_domain", f"Domain(s) resemble brand(s): {', '.join(lookalike_brands)}")
    if any_homograph:
        add(True, "homograph_domain", "Domain uses punycode/homograph characters")

    score = max(0, min(100, score))
    if score >= thresholds.get("high", 60):
        level = "high"
    elif score >= thresholds.get("medium", 30):
        level = "medium"
    else:
        level = "low"

    return RiskScoreResult(
        score=score,
        level=level,
        reasons=reasons,
        header_result=header_result,
        link_results=link_results,
        domain_matches=domain_matches,
    )
