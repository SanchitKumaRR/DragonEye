"""Scope engine tests - the part that must never be wrong."""

from __future__ import annotations

import pytest

from dragoneye.scope import Scope, ScopeError, normalize_host, parse_rule


def scope(in_scope, out_scope=(), **kwargs):
    return Scope(in_scope, out_scope, **kwargs)


# --- normalisation --------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("https://api.example.com:8443/v1/x?y=1", "api.example.com"),
        ("api.example.com:443", "api.example.com"),
        ("user:pass@api.example.com", "api.example.com"),
        ("api.example.com.", "api.example.com"),
        ("http://10.1.2.3:8080/x", "10.1.2.3"),
        ("[2001:db8::1]:443", "2001:db8::1"),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_normalize_rejects_empty():
    with pytest.raises(ScopeError):
        normalize_host("   ")


# --- rule parsing ---------------------------------------------------------


def test_bare_domain_matches_apex_and_subdomains():
    rule = parse_rule("example.com")
    assert rule.matches("example.com")
    assert rule.matches("a.example.com")
    assert rule.matches("a.b.example.com")
    assert not rule.matches("notexample.com")
    assert not rule.matches("example.com.evil.tld")


def test_wildcard_excludes_apex():
    rule = parse_rule("*.example.com")
    assert rule.matches("a.example.com")
    assert not rule.matches("example.com")


def test_leading_dot_is_wildcard():
    rule = parse_rule(".example.com")
    assert rule.kind == "wildcard"
    assert rule.matches("api.example.com")
    assert not rule.matches("example.com")


def test_cidr_and_ip_rules():
    cidr = parse_rule("10.10.0.0/16")
    assert cidr.matches("10.10.4.4")
    assert not cidr.matches("10.11.4.4")
    single = parse_rule("203.0.113.7")
    assert single.matches("203.0.113.7")
    assert not single.matches("203.0.113.8")


def test_regex_rule():
    rule = parse_rule(r"re:^api\d+\.")
    assert rule.matches("api12.example.com")
    assert not rule.matches("www.example.com")


def test_asn_rule_is_rejected_clearly():
    with pytest.raises(ScopeError, match="ASN rules are not supported"):
        parse_rule("AS15169")


def test_bad_url_port_is_scope_error():
    with pytest.raises(ScopeError):
        parse_rule("https://example.com:notaport")
    with pytest.raises(ScopeError):
        normalize_host("https://example.com:99999")


def test_url_rule_reduces_to_host():
    rule = parse_rule("https://app.example.com/login")
    assert rule.kind == "domain"
    assert rule.value == "app.example.com"


def test_port_qualified_rule_is_flagged():
    rule = parse_rule("example.com:8443")
    assert rule.port == 8443
    assert "port" in (rule.note or "")


def test_bad_regex_raises():
    with pytest.raises(ScopeError):
        parse_rule("re:[")


def test_mid_label_wildcard_rejected():
    with pytest.raises(ScopeError):
        parse_rule("api.*.example.com")


def test_junk_rule_rejected():
    with pytest.raises(ScopeError):
        parse_rule("not a domain!!")


def test_empty_rule_rejected():
    with pytest.raises(ScopeError):
        parse_rule("   ")


# --- decisions ------------------------------------------------------------


def test_allow_and_deny_precedence():
    s = scope(["example.com", "*.example.com"], ["admin.example.com"])
    assert s.in_scope("www.example.com")
    assert not s.in_scope("admin.example.com")  # deny wins even though *.example.com matches
    assert s.check("admin.example.com").reason.startswith("matched out-of-scope")


def test_unmatched_is_denied():
    s = scope(["example.com"])
    decision = s.check("example.org")
    assert not decision.allowed
    assert "not matched" in decision.reason


def test_no_in_scope_rules_refuses_to_build():
    with pytest.raises(ScopeError):
        Scope([], ["example.com"])


def test_comments_and_blank_lines_ignored():
    s = scope(["# comment", "", "  example.com  "])
    assert s.in_scope("example.com")


def test_metadata_endpoint_always_blocked():
    s = scope(["169.254.169.254", "169.254.0.0/16"], allow_private=True)
    assert not s.in_scope("169.254.169.254")

def test_private_blocked_by_default():
    s = scope(["10.0.0.0/8"])
    assert not s.in_scope("10.1.2.3")
    assert "private" in s.check("10.1.2.3").reason


def test_private_allowed_with_flag():
    s = scope(["10.0.0.0/8"], allow_private=True)
    assert s.in_scope("10.1.2.3")


def test_ipv6_cidr():
    s = scope(["2001:db8::/32"], allow_private=True)
    assert s.in_scope("2001:db8::5")
    assert not s.in_scope("2001:dead::5")


def test_filter_splits_and_dedupes():
    s = scope(["example.com"])
    allowed, rejected = s.filter(["a.example.com", "a.example.com", "evil.org"])
    assert allowed == ["a.example.com"]
    assert len(rejected) == 1


def test_check_url_with_path():
    s = scope(["example.com"])
    assert s.in_scope("https://deep.path.example.com/x/y?z=1")


def test_roots_only_domains():
    s = scope(["example.com", "*.other.com", "10.0.0.0/8", "re:x"])
    assert s.roots() == ["example.com"]


def test_roots_include_single_ips_but_not_cidrs():
    s = scope(["127.0.0.1", "10.0.0.0/8"])
    assert s.roots() == ["127.0.0.1"]


# --- resolved hostnames ---------------------------------------------------


def test_hostname_allowed_by_resolved_cidr():
    s = scope(["10.10.0.0/16"], allow_private=True)
    assert not s.in_scope("host.inside.example")
    assert s.in_scope("host.inside.example", ["10.10.4.4"])
    assert not s.in_scope("host.elsewhere.example", ["10.11.4.4"])


def test_hostname_resolving_into_deny_cidr_is_denied():
    s = scope(["example.com"], ["93.184.216.0/24"])
    decision = s.check("www.example.com", ["93.184.216.34"])
    assert not decision.allowed
    assert "out-of-scope" in decision.reason


def test_hostname_resolving_to_private_or_metadata_is_denied():
    s = scope(["example.com"])
    assert not s.check("www.example.com", ["10.0.0.5"]).allowed
    assert not s.check("www.example.com", ["169.254.169.254"]).allowed


def test_filter_accepts_resolved_map():
    s = scope(["10.10.0.0/16"], allow_private=True)
    allowed, rejected = s.filter(
        ["a.example", "b.example"], resolved={"a.example": ["10.10.1.1"]}
    )
    assert allowed == ["a.example"]
    assert len(rejected) == 1

