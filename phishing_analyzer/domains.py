"""M4 - Lookalike / typosquat / homograph domain detection.

No external dependency for edit distance (a small stdlib-only Levenshtein
implementation is plenty fast for domain-length strings). Homograph
detection is limited to spotting punycode ("xn--") labels or non-ASCII
domains - the tool doesn't attempt full Unicode confusable-character
mapping in Phase 1.

Naive SLD (second-level-domain) extraction is used (no public suffix
list), so domains under multi-part TLDs like "co.uk" will be handled
a bit crudely. Documented limitation, acceptable for a v1 heuristic tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from phishing_analyzer.datafiles import load_brand_domains

_SEGMENT_RE = re.compile(r"[^a-z0-9]+")


@dataclass
class DomainMatch:
    domain: str
    matched_brand: str
    match_type: str  # "typosquat" | "combosquat" | "homograph"
    edit_distance: int | None = None


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _registrable_label(domain: str) -> str:
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return domain.lower()
    return parts[-2]


def _segments(label: str) -> list[str]:
    return [s for s in _SEGMENT_RE.split(label) if s]


def _try_decode_idna(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def check_lookalike_domain(domain: str) -> list[DomainMatch]:
    """Return every lookalike/homograph match found for a single domain."""
    domain = (domain or "").lower().strip(".")
    matches: list[DomainMatch] = []
    if not domain:
        return matches

    labels = domain.split(".")
    if any(label.startswith("xn--") for label in labels) or not domain.isascii():
        decoded = _try_decode_idna(domain)
        matches.append(DomainMatch(domain=domain, matched_brand=decoded, match_type="homograph"))

    sld = _registrable_label(domain)
    domain_segments = _segments(sld)

    for brand_domain in load_brand_domains():
        if domain == brand_domain or domain.endswith("." + brand_domain):
            continue  # legitimate brand domain or a subdomain of it

        brand_token = brand_domain.split(".")[0]
        if len(brand_token) < 3:
            continue

        for seg in domain_segments:
            if seg == brand_token:
                matches.append(
                    DomainMatch(
                        domain=domain,
                        matched_brand=brand_domain,
                        match_type="combosquat",
                        edit_distance=0,
                    )
                )
                break
            if abs(len(seg) - len(brand_token)) <= 2:
                dist = levenshtein(seg, brand_token)
                if 1 <= dist <= 2:
                    matches.append(
                        DomainMatch(
                            domain=domain,
                            matched_brand=brand_domain,
                            match_type="typosquat",
                            edit_distance=dist,
                        )
                    )
                    break

    return matches


def check_lookalike_domains(domains: list[str]) -> list[DomainMatch]:
    """Convenience wrapper for scoring.py - checks a list of unique domains."""
    all_matches: list[DomainMatch] = []
    seen = set()
    for domain in domains:
        if not domain or domain in seen:
            continue
        seen.add(domain)
        all_matches.extend(check_lookalike_domain(domain))
    return all_matches
