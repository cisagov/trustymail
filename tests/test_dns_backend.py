"""Exercise the selected DNS backend without external DNS or SMTP queries."""

# Standard Python Libraries
from types import SimpleNamespace
from unittest.mock import Mock

# Third-Party Libraries
import dns.exception
import pytest
import spf

# cisagov Libraries
from trustymail import trustymail


def test_spf_uses_dnspython(monkeypatch):
    """Preserve SPF lookups using the already preferred dnspython backend."""
    query = Mock(return_value=[SimpleNamespace(address="192.0.2.1")])
    monkeypatch.setattr(spf.dns.resolver, "query", query)
    assert spf.DNSLookup is spf.DNSLookup_dnspython
    assert spf.DNSLookup("example.test", "A", timeout=7) == [
        (("example.test", "A"), "192.0.2.1")
    ]
    query.assert_called_once_with("example.test", "A", lifetime=7)


def test_spf_dns_timeout_remains_temporary(monkeypatch):
    """Continue translating a DNS timeout to the SPF temporary-error API."""
    monkeypatch.setattr(
        spf.dns.resolver, "query", Mock(side_effect=dns.exception.Timeout)
    )
    with pytest.raises(spf.TempError):
        spf.DNSLookup("example.test", "TXT", timeout=7)


def test_scan_preserves_explicit_resolver_settings(monkeypatch):
    """Retain custom server and timeout settings without the legacy backend."""
    domain = Mock(is_live=True)
    monkeypatch.setattr(trustymail, "Domain", Mock(return_value=domain))
    scan = Mock()
    monkeypatch.setattr(trustymail, "mx_scan", scan)
    result = trustymail.scan(
        "example.test",
        7,
        5,
        "localhost",
        [25],
        {},
        {"mx": True, "starttls": False, "spf": False, "dmarc": False},
        ["192.0.2.53"],
    )
    assert result is domain
    scan.assert_called_once()
    resolver, scanned_domain = scan.call_args[0]
    assert scanned_domain is domain
    assert resolver.timeout == resolver.lifetime == 7.0
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.retry_servfail is False
    assert trustymail.DNS_RESOLVERS == ["192.0.2.53"]
    assert trustymail.DNS_TIMEOUT == 7
