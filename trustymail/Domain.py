from publicsuffix import PublicSuffixList

from trustymail import TrustyMail

public_list = PublicSuffixList()


class Domain:

    base_domains = {}

    def __init__(self, domain_name):
        self.domain_name = domain_name

        self.base_domain_name = public_list.get_public_suffix(domain_name)

        if self.base_domain_name != self.domain_name:
            if self.base_domain_name not in Domain.base_domains:
                domain = Domain(self.base_domain_name)
                # Populate DMARC for parent.
                TrustyMail.dmarc_scan(domain)
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

        # Syntax validity - default spf to false as the lack of an SPF is a bad thing.
        self.valid_spf = False
        self.valid_dmarc = True
        self.syntax_errors = []

        # Mail Info
        self.mail_servers = []

        # A list of any errors that occurred while scanning records.
        self.errors = []

    def has_mail(self):
        return len(self.mail_servers) > 0

    def has_spf(self):
        return len(self.spf) > 0

    def has_dmarc(self):
        return len(self.dmarc) > 0

    def add_mx_record(self, record):
        self.mx_records.append(record)
        self.mail_servers.append(record[1])

    def parent_has_dmarc(self):
        if self.base_domain is None:
            return None
        return self.base_domain.has_dmarc()

    def parent_valid_dmarc(self):
        if self.base_domain is None:
            return None
        return self.base_domain.valid_dmarc

    def parent_dmarc_results(self):
        if self.base_domain is None:
            return None
        return self.format_list(self.base_domain.dmarc)

    def generate_results(self):
        results = {
                        "Domain": self.domain_name,
                        "Base Domain": self.base_domain_name,
                        "Live": self.is_live,

                        "Sends Mail": self.has_mail(),
                        "Mail Servers": self.format_list(self.mail_servers),

                        "SPF Record": self.has_spf(),
                        "Valid SPF": self.valid_spf,
                        "SPF Results": self.format_list(self.spf),

                        "DMARC Record": self.has_dmarc(),
                        "Valid DMARC": self.valid_dmarc,
                        "DMARC Results": self.format_list(self.dmarc),

                        "DMARC Record on Base Domain": self.parent_has_dmarc(),
                        "Valid DMARC Record on Base Domain": self.parent_valid_dmarc(),
                        "DMARC Results on Base Domain": self.parent_dmarc_results(),

                        "Syntax Errors": self.format_list(self.syntax_errors)

                  }

        return results

    # Format a list into a string to increase readability in CSV.
    def format_list(self, record_list):

        if not record_list:
            return ""

        return ", ".join(record_list)
