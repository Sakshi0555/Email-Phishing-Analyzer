from phishing_analyzer.domains import (
    check_lookalike_domain,
    check_lookalike_domains,
    levenshtein,
)


def test_levenshtein_basic():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("", "abc") == 3


def test_legit_brand_domain_and_subdomain_not_flagged():
    assert check_lookalike_domain("paypal.com") == []
    assert check_lookalike_domain("mail.paypal.com") == []


def test_typosquat_detected():
    matches = check_lookalike_domain("paypa1-support.com")
    assert len(matches) == 1
    assert matches[0].match_type == "typosquat"
    assert matches[0].matched_brand == "paypal.com"
    assert matches[0].edit_distance == 1


def test_combosquat_detected():
    matches = check_lookalike_domain("paypal-security-verify.com")
    assert any(m.match_type == "combosquat" and m.matched_brand == "paypal.com" for m in matches)


def test_homograph_flagged_for_punycode_label():
    matches = check_lookalike_domain("xn--pypal-4ve.com")
    assert any(m.match_type == "homograph" for m in matches)


def test_unrelated_domain_not_flagged():
    assert check_lookalike_domain("examplecorp.com") == []


def test_batch_helper_ignores_ip_and_shortener_false_positives():
    matches = check_lookalike_domains(["203.0.113.5", "bit.ly", "paypa1-support.com"])
    assert len(matches) == 1
    assert matches[0].matched_brand == "paypal.com"
