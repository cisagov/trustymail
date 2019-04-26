from datetime import datetime, timedelta
from collections import OrderedDict
from os import path, stat

import publicsuffix

from trustymail import PublicSuffixListReadOnly
from trustymail import PublicSuffixListFilename
from trustymail import trustymail


def get_psl():
    """
    Gets the Public Suffix List - either new, or cached in the CWD for 24 hours

    Returns
    -------
    PublicSuffixList: An instance of PublicSuffixList loaded with a cached or updated list
    """

    def download_psl():
        fresh_psl = publicsuffix.fetch()
        with open(PublicSuffixListFilename, 'w', encoding='utf-8') as fresh_psl_file:
            fresh_psl_file.write(fresh_psl.read())

    # Download the psl if necessary
    if not PublicSuffixListReadOnly:
        if not path.exists(PublicSuffixListFilename):
            download_psl()
        else:
            psl_age = datetime.now() - datetime.fromtimestamp(stat(PublicSuffixListFilename).st_mtime)
            if psl_age > timedelta(hours=24):
                download_psl()

    with open(PublicSuffixListFilename, encoding='utf-8') as psl_file:
        psl = publicsuffix.PublicSuffixList(psl_file)

    return psl


def get_public_suffix(domain):
    """Returns the public suffix of a given domain"""
    public_list = get_psl()

    return public_list.get_public_suffix(domain)


def format_list(record_list):
    """Format a list into a string to increase readability in CSV"""
    # record_list should only be a list, not an integer, None, or
    # anything else.  Thus this if clause handles only empty
    # lists.  This makes a "null" appear in the JSON output for
    # empty lists, as expected.
    if not record_list:
        return None

    return ', '.join(record_list)


class Domain:
    base_domains = {}

    def __init__(self, domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, dns_hostnames):
        self.domain_name = domain_name.lower()

        self.base_domain_name = get_public_suffix(self.domain_name)

        self.is_base_domain = True
        self.base_domain = None
        if self.base_domain_name != self.domain_name:
            self.is_base_domain = False
            if self.base_domain_name not in Domain.base_domains:
                # Populate DMARC for parent.
                domain = trustymail.scan(self.base_domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, {'mx': False, 'starttls': False, 'spf': False, 'dmarc': True}, dns_hostnames)
                Domain.base_domains[self.base_domain_name] = domain
            self.base_domain = Domain.base_domains[self.base_domain_name]

        # Start off assuming the host is live unless an error tells us otherwise.
        self.is_live = True

        # Keep entire record for potential future use.
        self.mx_records = None
        self.mx_records_dnssec = None
        self.spf = None
        self.spf_dnssec = None
        self.dmarc = None
        self.dmarc_dnssec = False
        self.dmarc_policy = None
        self.dmarc_subdomain_policy = None
        self.dmarc_pct = None
        self.dmarc_aggregate_uris = []
        self.dmarc_forensic_uris = []
        self.dmarc_has_aggregate_uri = False
        self.dmarc_has_forensic_uri = False
        self.dmarc_reports_address_error = False

        # Syntax validity - default spf to false as the lack of an SPF is a bad thing.
        self.valid_spf = False
        self.valid_dmarc = True
        self.syntax_errors = []

        # Mail Info
        self.mail_servers = None

        # A dictionary for each port for each entry in mail_servers.
        # The dictionary's values indicate:
        # 1. Whether or not the server is listening on the port
        # 2. Whether or not the server supports SMTP
        # 3. Whether or not the server supports STARTTLS
        self.starttls_results = {}

        # A list of any debugging information collected while scanning records.
        self.debug_info = []

        # A list of the ports tested for SMTP
        self.ports_tested = set()

    def has_mail(self):
        if self.mail_servers is not None:
            return len(self.mail_servers) > 0
        return None

    def has_supports_smtp(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support SMTP.
        """
        result = None
        if len(self.starttls_results) > 0:
            result = len(filter(lambda x: self.starttls_results[x]['supports_smtp'],
                                self.starttls_results.keys())) > 0
        return result

    def has_starttls(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support STARTTLS.
        """
        result = None
        if len(self.starttls_results) > 0:
            result = len(filter(lambda x: self.starttls_results[x]['starttls'],
                                self.starttls_results.keys())) > 0
        return result

    def has_spf(self):
        if self.spf is not None:
            return len(self.spf) > 0
        return None

    def has_dmarc(self):
        if self.dmarc is not None:
            return len(self.dmarc) > 0
        return None

    def add_mx_record(self, record):
        if self.mx_records is None:
            self.mx_records = []
        self.mx_records.append(record)
        # The rstrip is because dnspython's string representation of
        # the record will contain a trailing period if it is a FQDN.
        if self.mail_servers is None:
            self.mail_servers = []
        self.mail_servers.append(record.exchange.to_text().rstrip('.').lower())

    def parent_has_dmarc(self):
        ans = self.has_dmarc()
        if self.base_domain:
            ans = self.base_domain.has_dmarc()
        return ans

    def parent_dmarc_dnssec(self):
        ans = self.dmarc_dnssec
        if self.base_domain:
            ans = self.base_domain.dmarc_dnssec
        return ans

    def parent_valid_dmarc(self):
        ans = self.valid_dmarc
        if self.base_domain:
            return self.base_domain.valid_dmarc
        return ans

    def parent_dmarc_results(self):
        ans = format_list(self.dmarc)
        if self.base_domain:
            ans = format_list(self.base_domain.dmarc)
        return ans

    def get_dmarc_policy(self):
        ans = self.dmarc_policy
        # If the policy was never set, or isn't in the list of valid
        # policies, check the parents.
        if ans is None or ans.lower() not in ['quarantine', 'reject', 'none']:
            if self.base_domain:
                # We check the *subdomain* policy in case one was
                # explicitly set.  If one was not explicitly set then
                # the subdomain policy is populated with the value for
                # the domain policy by trustymail.py anyway, in
                # accordance with the RFC
                # (https://tools.ietf.org/html/rfc7489#section-6.3).
                ans = self.base_domain.get_dmarc_subdomain_policy()
            else:
                ans = None
        return ans

    def get_dmarc_subdomain_policy(self):
        ans = self.dmarc_subdomain_policy
        # If the policy was never set, or isn't in the list of valid
        # policies, check the parents.
        if ans is None or ans.lower() not in ['quarantine', 'reject', 'none']:
            if self.base_domain:
                ans = self.base_domain.get_dmarc_subdomain_policy()
            else:
                ans = None
        return ans

    def get_dmarc_pct(self):
        ans = self.dmarc_pct
        if not ans and self.base_domain:
            # Check the parents
            ans = self.base_domain.get_dmarc_pct()
        return ans

    def get_dmarc_has_aggregate_uri(self):
        ans = self.dmarc_has_aggregate_uri
        # If there are no aggregate URIs then check the parents.
        if not ans and self.base_domain:
            ans = self.base_domain.get_dmarc_has_aggregate_uri()
        return ans

    def get_dmarc_has_forensic_uri(self):
        ans = self.dmarc_has_forensic_uri
        # If there are no forensic URIs then check the parents.
        if not ans and self.base_domain:
            ans = self.base_domain.get_dmarc_has_forensic_uri()
        return ans

    def get_dmarc_aggregate_uris(self):
        ans = self.dmarc_aggregate_uris
        # If there are no aggregate URIs then check the parents.
        if not ans and self.base_domain:
            ans = self.base_domain.get_dmarc_aggregate_uris()
        return ans

    def get_dmarc_forensic_uris(self):
        ans = self.dmarc_forensic_uris
        # If there are no forensic URIs then check the parents.
        if not ans and self.base_domain:
            ans = self.base_domain.get_dmarc_forensic_uris()
        return ans

    def generate_results(self):
        if len(self.starttls_results.keys()) == 0:
            domain_supports_smtp = None
            domain_supports_starttls = None
            mail_servers_that_support_smtp = None
            mail_servers_that_support_starttls = None
        else:
            mail_servers_that_support_smtp = [x for x in self.starttls_results.keys() if self.starttls_results[x][
                'supports_smtp']]
            mail_servers_that_support_starttls = [x for x in self.starttls_results.keys() if self.starttls_results[x][
                'starttls']]
            domain_supports_smtp = bool(mail_servers_that_support_smtp)
            domain_supports_starttls = domain_supports_smtp and all([self.starttls_results[x]['starttls'] for x in mail_servers_that_support_smtp])

        results = OrderedDict([
            ('Domain', self.domain_name),
            ('Base Domain', self.base_domain_name),
            ('Live', self.is_live),

            ('MX Record', self.has_mail()),
            ('MX Record DNSSEC', self.mx_records_dnssec),
            ('Mail Servers', format_list(self.mail_servers)),
            ('Mail Server Ports Tested', format_list([str(port) for port in self.ports_tested])),
            ('Domain Supports SMTP Results', format_list(mail_servers_that_support_smtp)),
            # True if and only if at least one mail server speaks SMTP
            ('Domain Supports SMTP', domain_supports_smtp),
            ('Domain Supports STARTTLS Results', format_list(mail_servers_that_support_starttls)),
            # True if and only if all mail servers that speak SMTP
            # also support STARTTLS
            ('Domain Supports STARTTLS', domain_supports_starttls),

            ('SPF Record', self.has_spf()),
            ('SPF Record DNSSEC', self.spf_dnssec),
            ('Valid SPF', self.valid_spf),
            ('SPF Results', format_list(self.spf)),

            ('DMARC Record', self.has_dmarc()),
            ('DMARC Record DNSSEC', self.dmarc_dnssec),
            ('Valid DMARC', self.has_dmarc() and self.valid_dmarc),
            ('DMARC Results', format_list(self.dmarc)),

            ('DMARC Record on Base Domain', self.parent_has_dmarc()),
            ('DMARC Record on Base Domain DNSSEC', self.parent_dmarc_dnssec()),
            ('Valid DMARC Record on Base Domain', self.parent_has_dmarc() and self.parent_valid_dmarc()),
            ('DMARC Results on Base Domain', self.parent_dmarc_results()),
            ('DMARC Policy', self.get_dmarc_policy()),
            ('DMARC Subdomain Policy', self.get_dmarc_subdomain_policy()),
            ('DMARC Policy Percentage', self.get_dmarc_pct()),

            ("DMARC Aggregate Report URIs", format_list(self.get_dmarc_aggregate_uris())),
            ("DMARC Forensic Report URIs", format_list(self.get_dmarc_forensic_uris())),

            ('DMARC Has Aggregate Report URI', self.get_dmarc_has_aggregate_uri()),
            ('DMARC Has Forensic Report URI', self.get_dmarc_has_forensic_uri()),
            ('DMARC Reporting Address Acceptance Error', self.dmarc_reports_address_error),

            ('Syntax Errors', format_list(self.syntax_errors)),
            ('Debug Info', format_list(self.debug_info))
        ])

        return results
