"""Tests for AcdpSsrfPolicy — synchronous SSRF verdicts.

Build with `maturin develop` from `bindings/acdp-py/`, then run `pytest`.
These pin the binding's SSRF classification (and its stable `reason`
taxonomy) against the Rust core so a host can stop re-implementing the
range tables in Python.
"""
import pytest

import acdp


def _prod():
    return acdp.AcdpSsrfPolicy.production()


def test_ssrf_rejected_is_exported_exception():
    assert issubclass(acdp.SsrfRejected, Exception)


def test_https_public_host_allowed():
    # No exception → allowed.
    assert _prod().check_url("https://registry.example.com") is None


def test_http_scheme_rejected_as_non_https():
    with pytest.raises(acdp.SsrfRejected) as ei:
        _prod().check_url("http://registry.example.com")
    assert ei.value.reason == "non_https"


def test_ip_literal_rejected():
    with pytest.raises(acdp.SsrfRejected) as ei:
        _prod().check_url("https://192.168.1.1")
    assert ei.value.reason == "ip_literal"
    with pytest.raises(acdp.SsrfRejected) as ei6:
        _prod().check_url("https://[::1]")
    assert ei6.value.reason == "ip_literal"


def test_malformed_url_rejected_as_invalid_url():
    with pytest.raises(acdp.SsrfRejected) as ei:
        _prod().check_url("not a url")
    assert ei.value.reason == "invalid_url"


@pytest.mark.parametrize(
    "ip,reason",
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "private"),
        ("172.16.5.5", "private"),
        ("192.168.1.1", "private"),
        ("100.64.0.1", "private"),
        ("169.254.169.254", "imds"),
        ("239.0.0.1", "multicast_or_reserved"),
        ("0.0.0.1", "multicast_or_reserved"),
        ("240.0.0.1", "multicast_or_reserved"),
        ("::1", "loopback"),
        ("fc00::1", "private"),
        ("fe80::1", "imds"),
        ("64:ff9b::a9fe:a9fe", "imds"),
        ("::ffff:10.0.0.1", "private"),
    ],
)
def test_check_ip_reason_taxonomy(ip, reason):
    with pytest.raises(acdp.SsrfRejected) as ei:
        _prod().check_ip(ip)
    assert ei.value.reason == reason


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.1", "2001:db8::1"])
def test_check_ip_allows_public(ip):
    assert _prod().check_ip(ip) is None


def test_check_ip_rejects_garbage_with_value_error():
    # A non-address string is a ValueError, not an SsrfRejected.
    with pytest.raises(ValueError):
        _prod().check_ip("not-an-ip")


def test_allow_test_loopback_permits_loopback_only():
    pol = acdp.AcdpSsrfPolicy.allow_test_loopback()
    # Loopback now allowed...
    assert pol.check_ip("127.0.0.1") is None
    assert pol.check_ip("::1") is None
    # ...but every other forbidden range still rejected.
    with pytest.raises(acdp.SsrfRejected) as ei:
        pol.check_ip("10.0.0.1")
    assert ei.value.reason == "private"


def test_redirect_same_authority_allowed():
    assert (
        _prod().check_redirect_authority(
            "https://a.example/x", "https://a.example/y"
        )
        is None
    )


def test_redirect_explicit_443_equals_default():
    # D2: explicit :443 must compare equal to the implicit https default.
    assert (
        _prod().check_redirect_authority(
            "https://a.example/x", "https://a.example:443/y"
        )
        is None
    )


@pytest.mark.parametrize(
    "frm,to",
    [
        ("https://a.example/x", "https://b.example/y"),  # cross host
        ("https://a.example/x", "https://a.example:8443/y"),  # port change
        ("https://a.example/x", "http://a.example/y"),  # scheme downgrade
    ],
)
def test_redirect_cross_authority_rejected(frm, to):
    with pytest.raises(acdp.SsrfRejected) as ei:
        _prod().check_redirect_authority(frm, to)
    assert ei.value.reason == "cross_authority"
