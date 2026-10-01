from apps.tldsquatting.classify import classify_lookalike, ns_operators, _is_redacted_registrant


def _rec(**kw):
    base = dict(candidate="x.com", ns_targets=[], has_a=True, has_aaaa=False, has_mx=False,
                has_spf=False, has_dmarc=False, brand_mentioned=False, parked=False,
                content_checked=True, predates_target=False, registrant=None)
    base.update(kw); return base


def test_ns_operators_reduces_to_registrable():
    assert ns_operators(["ns1.zoho.com.", "ns2.zoho.com."]) == {"zoho.com"}


def test_pre_existing_wins():
    assert classify_lookalike(_rec(predates_target=True, brand_mentioned=True), {"zoho.com"}, None, None) == "pre_existing"


def test_owned_by_ns_match_even_with_brand():
    # a domain on YOUR nameservers is yours; brand mention is expected there.
    assert classify_lookalike(_rec(ns_targets=["ns1.zoho.com."], brand_mentioned=True),
                              {"zoho.com"}, None, None) == "owned"


def test_owned_by_registrant_match():
    assert classify_lookalike(_rec(registrant="Zoho Corp"), {"other.com"}, "zoho corp", None) == "owned"


def test_brand_mention_forces_threat_when_not_owned():
    assert classify_lookalike(_rec(ns_targets=["ns1.evil.com."], brand_mentioned=True),
                              {"zoho.com"}, None, None) == "threat"


def test_email_only_forces_threat():
    r = _rec(has_a=False, has_aaaa=False, has_mx=True, content_checked=False)
    assert classify_lookalike(r, {"zoho.com"}, None, None) == "threat"


def test_parked_when_no_brand_no_owned():
    assert classify_lookalike(_rec(ns_targets=["ns.parkingcrew.net."], parked=True),
                              {"zoho.com"}, None, None) == "parked"


def test_unrelated_diff_ns_no_brand_own_content():
    assert classify_lookalike(_rec(ns_targets=["ns1.somehost.com."], has_a=True, content_checked=True),
                              {"zoho.com"}, None, None) == "unrelated"


def test_unrelated_with_login_form_still_unrelated():
    # postman.catering: login form but no brand mention, different NS → unrelated.
    r = _rec(ns_targets=["ns1.gandi.net."], has_a=True, content_checked=True, brand_mentioned=False)
    assert classify_lookalike(r, {"postman.com"}, None, None) == "unrelated"


def test_resolving_no_content_check_is_threat():
    # has_a but homepage never fetched (content_checked False) and no other signal → threat (don't collapse blindly)
    assert classify_lookalike(_rec(ns_targets=["ns1.x.com."], content_checked=False),
                              {"zoho.com"}, None, None) == "threat"


def test_shared_privacy_proxy_registrant_does_not_hide_brand_impersonator():
    # Two unrelated domains behind the same GDPR privacy-proxy registrant must NOT
    # match on registrant alone — the impersonator has to surface as threat.
    r = _rec(registrant="Withheld for Privacy ehf.", brand_mentioned=True)
    assert classify_lookalike(r, {"other.com"}, "Withheld for Privacy ehf.", None) == "threat"


def test_real_distinct_registrant_match_still_owned():
    r = _rec(registrant="Zoho Corporation Pvt. Ltd.")
    assert classify_lookalike(r, {"other.com"}, "Zoho Corporation Pvt. Ltd.", None) == "owned"


def test_is_redacted_registrant_true_cases():
    for value in [
        "REDACTED FOR PRIVACY",
        "Withheld for Privacy ehf.",
        "Domains By Proxy, LLC",
        "Contact Privacy Inc.",
        "Perfect Privacy, LLC",
        "Identity Protection Service",
        "Whois Privacy",
        "Data Protected",
        "Not Disclosed",
        "GDPR Masked",
        "Private Registrant",
        "Registration on behalf of a domain owner",
        "",
        None,
    ]:
        assert _is_redacted_registrant(value) is True


def test_is_redacted_registrant_false_for_real_org():
    assert _is_redacted_registrant("Zoho Corporation Pvt. Ltd.") is False
