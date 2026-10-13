"""Exercise scanning with the dnspython backend."""

# Standard Python Libraries
from types import SimpleNamespace
from unittest.mock import Mock

# Third-Party Libraries
import dns.resolver
import dns.rrset
import pytest

# cisagov Libraries
from trustymail import cli, trustymail


def test_cli_import():
    """Load the entry point with the installed DNS dependencies."""
    assert callable(cli.main)


def test_scan_dns_configuration(monkeypatch):
    """Initialize a scan without requiring the legacy DNS backend."""
    domain = SimpleNamespace(is_live=True)
    monkeypatch.setattr(trustymail, "Domain", Mock(return_value=domain))
    mx_scan = Mock()
    monkeypatch.setattr(trustymail, "mx_scan", mx_scan)
    monkeypatch.setattr(trustymail, "DNS_TIMEOUT", None, raising=False)
    monkeypatch.setattr(trustymail, "DNS_RESOLVERS", None, raising=False)

    result = trustymail.scan(
        "example.com",
        7,
        5,
        "localhost",
        [25],
        False,
        {"mx": True, "starttls": False, "spf": False, "dmarc": False},
        ["192.0.2.53"],
    )

    assert result is domain
    mx_scan.assert_called_once()
    resolver, scanned_domain = mx_scan.call_args[0]
    assert scanned_domain is domain
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.timeout == resolver.lifetime == 7
    assert resolver.retry_servfail is False


@pytest.mark.parametrize(
    "included_record, valid",
    [("v=spf1 -all", True), ("v=spf1 invalid -all", False)],
)
def test_spf_include_uses_dnspython(monkeypatch, included_record, valid):
    """Validate SPF includes using real pyspf and local DNS responses."""

    def query(name, record_type, **kwargs):
        assert name == "sender.example"
        if record_type != "TXT":
            raise dns.resolver.NoAnswer
        return dns.rrset.from_text(name, 60, "IN", "TXT", '"' + included_record + '"')

    lookup = Mock(side_effect=query)
    monkeypatch.setattr(dns.resolver, "query", lookup)
    domain = SimpleNamespace(
        domain_name="example.com", valid_spf=None, debug_info=[], syntax_errors=[]
    )

    trustymail.check_spf_record("v=spf1 include:sender.example -all", domain)

    assert domain.valid_spf is valid
    assert any(call[0] == ("sender.example", "TXT") for call in lookup.call_args_list)
