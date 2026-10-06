"""Reporting destinations follow the selected DMARC record as a whole."""

# Standard Python Libraries
from contextlib import ExitStack
import unittest
from unittest.mock import Mock, patch

# Third-Party Libraries
import dns.rdata
import dns.rdataclass
import dns.rdatatype

# cisagov Libraries
from trustymail import trustymail


class DmarcReportInheritanceTest(unittest.TestCase):
    """Use actual domain parsing and result generation with fixed DNS answers."""

    def setUp(self):
        """Keep public-suffix and DNS lookups local to the test fixture."""
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(trustymail.Domain, "base_domains", {}))
        self.stack.enter_context(
            patch("trustymail.domain.get_public_suffix", return_value="example.test")
        )
        self.stack.enter_context(
            patch.object(trustymail, "get_public_suffix", return_value="example.test")
        )
        self.stack.enter_context(
            patch.object(trustymail, "check_dnssec", return_value=False)
        )
        self.parent = self.make_domain("example.test")
        self.parse(
            self.parent,
            "v=DMARC1; p=reject; rua=mailto:aggregate@example.test; "
            "ruf=mailto:failure@example.test",
        )
        trustymail.Domain.base_domains["example.test"] = self.parent
        self.child = self.make_domain("mail.example.test")

    @staticmethod
    def make_domain(name):
        """Construct the real domain object without opening SMTP connections."""
        return trustymail.Domain(name, 2, 2, "localhost", [25], {}, [])

    @staticmethod
    def parse(domain, record):
        """Run the real DMARC parser against one synthetic TXT response."""
        resolver = Mock()
        records = (
            []
            if record is None
            else [
                dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.TXT, '"' + record + '"'
                )
            ]
        )

        def answer(name, kind, tcp):
            if name != "_dmarc." + domain.domain_name or kind != "TXT" or not tcp:
                raise AssertionError("Unexpected external lookup")
            return records

        resolver.query.side_effect = answer
        trustymail.dmarc_scan(resolver, domain)

    def assert_reporting(self, aggregate, forensic):
        """Check list helpers, presence flags, and final report columns together."""
        self.assertEqual(self.child.get_dmarc_aggregate_uris(), aggregate)
        self.assertEqual(self.child.get_dmarc_forensic_uris(), forensic)
        self.assertEqual(self.child.get_dmarc_has_aggregate_uri(), bool(aggregate))
        self.assertEqual(self.child.get_dmarc_has_forensic_uri(), bool(forensic))
        result = self.child.generate_results()
        self.assertEqual(
            result["DMARC Aggregate Report URIs"], ", ".join(aggregate) or None
        )
        self.assertEqual(
            result["DMARC Forensic Report URIs"], ", ".join(forensic) or None
        )
        self.assertEqual(result["DMARC Has Aggregate Report URI"], bool(aggregate))
        self.assertEqual(result["DMARC Has Forensic Report URI"], bool(forensic))

    def test_local_record_without_reporting_tags_does_not_inherit_destinations(self):
        """A parent cannot supply omitted tags within a child's published policy."""
        for policy in ("none", "quarantine", "reject"):
            with self.subTest(policy=policy):
                self.child = self.make_domain("mail.example.test")
                self.parse(self.child, "v=DMARC1; p=" + policy)
                self.assertTrue(self.child.valid_dmarc)
                self.assert_reporting([], [])

    def test_aggregate_only_record_does_not_inherit_forensic_reporting(self):
        """Local aggregate reporting does not enable the parent's failure reports."""
        self.parse(self.child, "v=DMARC1; p=none; rua=mailto:local@example.test")
        self.assert_reporting(["mailto:local@example.test"], [])

    def test_forensic_only_record_does_not_inherit_aggregate_reporting(self):
        """Local failure reporting does not enable the parent's aggregate reports."""
        self.parse(self.child, "v=DMARC1; p=none; ruf=mailto:local@example.test")
        self.assert_reporting([], ["mailto:local@example.test"])

    def test_no_local_record_inherits_both_parent_destinations(self):
        """Whole-policy inheritance remains available when no local record exists."""
        self.parse(self.child, None)
        self.assert_reporting(
            ["mailto:aggregate@example.test"], ["mailto:failure@example.test"]
        )

    def test_local_destinations_remain_authoritative(self):
        """Existing explicit local reporting settings are unchanged."""
        self.parse(
            self.child,
            "v=DMARC1; p=none; rua=mailto:local-a@example.test; "
            "ruf=mailto:local-f@example.test",
        )
        self.assert_reporting(
            ["mailto:local-a@example.test"], ["mailto:local-f@example.test"]
        )

    def test_base_domain_without_destinations_still_reports_none(self):
        """A base domain has no parent reporting fallback."""
        self.child = self.make_domain("example.test")
        self.parse(self.child, "v=DMARC1; p=reject")
        self.assert_reporting([], [])

    def test_inherited_parent_without_reporting_tags_stays_disabled(self):
        """Absent reporting remains absent through genuine policy inheritance."""
        self.parent = self.make_domain("example.test")
        self.parse(self.parent, "v=DMARC1; p=reject")
        trustymail.Domain.base_domains["example.test"] = self.parent
        self.child = self.make_domain("mail.example.test")
        self.parse(self.child, None)
        self.assert_reporting([], [])


if __name__ == "__main__":
    unittest.main()
