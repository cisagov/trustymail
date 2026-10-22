"""Keep an explicit zero DMARC percentage in reported subdomain results."""

# Standard Python Libraries
import csv
import json
from unittest.mock import Mock

# Third-Party Libraries
import pytest

# cisagov Libraries
from trustymail import trustymail


@pytest.fixture
def domains(monkeypatch):
    """Create real domain objects without fetching DNS or public suffix data."""
    monkeypatch.setattr("trustymail.domain.get_public_suffix", lambda _: "example.test")
    monkeypatch.setattr(trustymail.Domain, "base_domains", {})
    options = {
        "timeout": 5,
        "smtp_timeout": 5,
        "smtp_localhost": "localhost",
        "smtp_ports": [25],
        "smtp_cache": {},
        "dns_hostnames": [],
    }
    parent = trustymail.Domain("example.test", **options)
    trustymail.Domain.base_domains["example.test"] = parent
    child = trustymail.Domain("sub.example.test", **options)
    return parent, child


@pytest.mark.parametrize("parent_pct", [None, 0, 25, 100])
@pytest.mark.parametrize("child_pct", [None, 0, 20, 100])
def test_percentage_inheritance(domains, parent_pct, child_pct):
    """Inherit a percentage only when the subdomain value is absent."""
    parent, child = domains
    parent.dmarc_pct = parent_pct
    child.dmarc_pct = child_pct
    expected = parent_pct if child_pct is None else child_pct
    assert child.get_dmarc_pct() == expected
    assert child.generate_results()["DMARC Policy Percentage"] == expected


@pytest.mark.parametrize("percentage", [None, 0, 25, 100])
def test_base_domain_percentage(domains, percentage):
    """Preserve the base domain's own percentage, including zero and None."""
    parent, _ = domains
    parent.dmarc_pct = percentage
    assert parent.get_dmarc_pct() == percentage


def test_parsed_zero_percentage_reaches_json_and_csv(domains, monkeypatch, tmp_path):
    """Parse DNS TXT fixtures and retain zero through both output serializers."""
    parent, child = domains
    records = {
        "_dmarc.example.test": "v=DMARC1; p=reject; pct=100",
        "_dmarc.sub.example.test": "v=DMARC1; p=reject; pct=0",
    }

    class TxtRecord:
        def __init__(self, text):
            self.text = text

        def to_text(self):
            return '"' + self.text + '"'

    def query(name, record_type, tcp):
        assert record_type == "TXT"
        assert tcp is True
        return [TxtRecord(records[name])]

    resolver = Mock()
    resolver.query.side_effect = query
    monkeypatch.setattr(trustymail, "check_dnssec", lambda *_: False)
    trustymail.dmarc_scan(resolver, parent)
    trustymail.dmarc_scan(resolver, child)
    assert parent.dmarc_pct == 100
    assert child.dmarc_pct == 0
    assert child.valid_dmarc
    assert child.get_dmarc_pct() == 0
    assert (
        json.loads(trustymail.generate_json([child]))[0]["DMARC Policy Percentage"] == 0
    )
    output = tmp_path / "results.csv"
    trustymail.generate_csv([child], output)
    with output.open(newline="", encoding="utf-8") as stream:
        assert next(csv.DictReader(stream))["DMARC Policy Percentage"] == "0"
    assert resolver.query.call_count == 2
