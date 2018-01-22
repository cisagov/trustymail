from os import path, stat
from datetime import datetime, timedelta
from collections import OrderedDict

import publicsuffix

from trustymail import trustymail


def get_psl():
    """
    Gets the Public Suffix List - either new, or cached in the CWD for 24 hours

    Returns
    -------
    PublicSuffixList: An instance of PublicSuffixList loaded with a cached or updated list
    """
    psl_path = 'public_suffix_list.dat'

    def download_psl():
        fresh_psl = publicsuffix.fetch()
        with open(psl_path, 'w', encoding='utf-8') as fresh_psl_file:
            fresh_psl_file.write(fresh_psl.read())

        return publicsuffix.PublicSuffixList(fresh_psl)

    if not path.exists(psl_path):
        psl = download_psl()
    else:
        psl_age = datetime.now() - datetime.fromtimestamp(stat(psl_path).st_mtime)
        if psl_age > timedelta(hours=24):
            psl = download_psl()
        else:
            with open(psl_path, encoding='utf-8') as psl_file:
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

        if self.base_domain_name != self.domain_name:
            if self.base_domain_name not in Domain.base_domains:
                # Populate DMARC for parent.
                domain = trustymail.scan(self.base_domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports,
                                         smtp_cache, {'mx': False, 'starttls': False, 'spf': False, 'dmarc': True},
                                         dns_hostnames)
                Domain.base_domains[self.base_domain_name] = domain
            self.base_domain = Domain.base_domains[self.base_domain_name]
        else:
            self.base_domain = None

        # Start off assuming the host is live unless an error tells us otherwise.
        self.is_live = True

        # Keep entire record for potential future use.
        self.mx_records = []
        self.spf = []
        self.dmarc = []
        self.dmarc_policy = None
        self.dmarc_pct = None
        self.dmarc_aggregate_uris = []
        self.dmarc_forensic_uris = []
        self.dmarc_has_aggregate_uri = False
        self.dmarc_has_forensic_uri = False

        # Syntax validity - default spf to false as the lack of an SPF is a bad thing.
        self.valid_spf = False
        self.valid_dmarc = True
        self.syntax_errors = []

        # Mail Info
        self.mail_servers = []

        # A dictionary for each port for each entry in mail_servers.
        # The dictionary's values indicate:
        # 1. Whether or not the server is listening on the port
        # 2. Whether or not the server supports SMTP
        # 3. Whether or not the server supports STARTTLS
        self.starttls_results = {}

        # A dictionary for each port for each entry in mail_server.
        # The dictionary's values indicate:
        # 1. Whether or not the server support the following Ciphers (TLS 1.0 - TLS 1.3):
        #    a. RC4
        #    b. 3DES
        # 2. Whether or not the server support the following Protocols:
        #    a. SSLv2
        #    b. SSLv3

        self.cipher_results = {}


        # A list of any debugging information collected while scanning records.
        self.debug_info = []

        # A list of the ports tested for SMTP
        self.ports_tested = set()

    def has_mail(self):
        return len(self.mail_servers) > 0

    def has_supports_smtp(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support SMTP.
        """
        return len(filter(lambda x: self.starttls_results[x]['supports_smtp'],
                          self.starttls_results.keys())) > 0

    def has_starttls(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support STARTTLS.
        """
        return len(filter(lambda x: self.starttls_results[x]['starttls'],
                          self.starttls_results.keys())) > 0


    def has_spf(self):
        return len(self.spf) > 0

    def has_dmarc(self):
        return len(self.dmarc) > 0

    def add_mx_record(self, record):
        self.mx_records.append(record)
        # The rstrip is because dnspython's string representation of
        # the record will contain a trailing period if it is a FQDN.
        self.mail_servers.append(record.exchange.to_text().rstrip('.').lower())

    def parent_has_dmarc(self):
        ans = self.has_dmarc()
        if self.base_domain:
            ans = self.base_domain.has_dmarc()
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
                ans = self.base_domain.get_dmarc_policy()
            else:
                ans = None
        return ans

    def generate_results(self):
        mail_servers_that_support_smtp = [x for x in self.starttls_results.keys() if self.starttls_results[x][
            'supports_smtp']]
        mail_servers_that_support_starttls = [x for x in self.starttls_results.keys() if self.starttls_results[x][
            'starttls']]
        domain_supports_smtp = bool(mail_servers_that_support_smtp)

        mail_servers_that_support_sslv2 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_sslv2']]
        mail_servers_that_support_sslv3 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_sslv3']]
        domain_supports_sslv2 = bool(mail_servers_that_support_sslv2)
        domain_supports_sslv3 = bool(mail_servers_that_support_sslv3)

        mail_servers_that_support_tls10_rc4 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls10_rc4']]
        mail_servers_that_support_tls11_rc4 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls11_rc4']]
        mail_servers_that_support_tls12_rc4 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls12_rc4']]
        mail_servers_that_support_tls13_rc4 = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls13_rc4']]

        domain_supports_rc4 = False if mail_servers_that_support_tls10_rc4 is False or \
                                       mail_servers_that_support_tls11_rc4 is False or \
                                       mail_servers_that_support_tls12_rc4 is False or \
                                       mail_servers_that_support_tls13_rc4 is False else True

        mail_servers_that_support_tls10_3des = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls10_3des']]
        mail_servers_that_support_tls11_3des = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls11_3des']]
        mail_servers_that_support_tls12_3des = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls12_3des']]
        mail_servers_that_support_tls13_3des = [x for x in self.cipher_results.keys() if self.cipher_results[x][
            'is_tls13_3des']]


        domain_supports_3des = False if mail_servers_that_support_tls10_3des is False or \
                                        mail_servers_that_support_tls11_3des is False or \
                                        mail_servers_that_support_tls12_3des is False or \
                                        mail_servers_that_support_tls13_3des is False else True

        domain_supports_cipher_results = False
        if domain_supports_3des is True or domain_supports_rc4 is True or domain_supports_sslv2 is True or domain_supports_sslv3 is True:
            domain_supports_cipher_results = True

        results = OrderedDict([
            ('Domain', self.domain_name),
            ('Base Domain', self.base_domain_name),
            ('Live', self.is_live),

            ('MX Record', self.has_mail()),
            ('Mail Servers', format_list(sorted(self.mail_servers))),
            ('Mail Server Ports Tested', format_list(sorted([str(port) for port in self.ports_tested]))),
            ('Domain Supports SMTP Results', format_list(sorted(mail_servers_that_support_smtp))),
            # True if and only if at least one mail server speaks SMTP
            ('Domain Supports SMTP', domain_supports_smtp),
            ('Domain Supports STARTTLS Results', format_list(sorted(mail_servers_that_support_starttls))),
            # True if and only if all mail servers that speak SMTP
            # also support STARTTLS
            ('Domain Supports STARTTLS', domain_supports_smtp and all([self.starttls_results[x]['starttls']
                                                                       for x in mail_servers_that_support_smtp])),
            ('Domain Supports Cipher Results', domain_supports_cipher_results),
            ('Domain Supports 3DES', domain_supports_3des),
            ('Domain Supports RC4', domain_supports_rc4),
            ('Domain Supports SSLv2', domain_supports_sslv2),
            ('Domain Supports SSLv3', domain_supports_sslv3),

            ('Domain Supports RC4 TLS 1.0', format_list(sorted(mail_servers_that_support_tls10_rc4))),
            ('Domain Supports RC4 TLS 1.1', format_list(sorted(mail_servers_that_support_tls11_rc4))),
            ('Domain Supports RC4 TLS 1.2', format_list(sorted(mail_servers_that_support_tls12_rc4))),
            ('Domain Supports RC4 TLS 1.3', format_list(sorted(mail_servers_that_support_tls13_rc4))),

            ('Domain Supports 3DES TLS 1.0', format_list(sorted(mail_servers_that_support_tls10_3des))),
            ('Domain Supports 3DES TLS 1.1', format_list(sorted(mail_servers_that_support_tls11_3des))),
            ('Domain Supports 3DES TLS 1.2', format_list(sorted(mail_servers_that_support_tls12_3des))),
            ('Domain Supports 3DES TLS 1.3', format_list(sorted(mail_servers_that_support_tls13_3des))),

            ('SPF Record', self.has_spf()),
            ('Valid SPF', self.valid_spf),
            ('SPF Results', format_list(self.spf)),

            ('DMARC Record', self.has_dmarc()),
            ('Valid DMARC', self.has_dmarc() and self.valid_dmarc),
            ('DMARC Results', format_list(self.dmarc)),

            ('DMARC Record on Base Domain', self.parent_has_dmarc()),
            ('Valid DMARC Record on Base Domain', self.parent_has_dmarc() and self.parent_valid_dmarc()),
            ('DMARC Results on Base Domain', self.parent_dmarc_results()),
            ('DMARC Policy', self.get_dmarc_policy()),
            ('DMARC Policy Percentage', self.dmarc_pct),

            ("DMARC Aggregate Report URIs", format_list(self.dmarc_aggregate_uris)),
            ("DMARC Forensic Report URIs", format_list(self.dmarc_forensic_uris)),

            ('DMARC Has Aggregate Report URI', self.dmarc_has_aggregate_uri),
            ('DMARC Has Forensic Report URI', self.dmarc_has_forensic_uri),


            ('Syntax Errors', format_list(self.syntax_errors)),
            ('Debug Info', format_list(self.debug_info))
        ])

        return results
