from publicsuffix import PublicSuffixList

from trustymail import trustymail

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
                trustymail.dmarc_scan(domain)
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

        # A list of any errors that occurred while scanning records.
        self.errors = []

        # A list of the ports tested for SMTP
        self.ports_tested = set()

    def has_mail(self):
        return len(self.mail_servers) > 0

    def has_supports_smtp(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support SMTP.
        """
        return len(filter(lambda x:self.starttls_results[x]["supports_smtp"],
                          self.starttls_results.keys())) > 0

    def has_starttls(self):
        """
        Returns True if any of the mail servers associated with this
        domain are listening and support STARTTLS.
        """
        return len(filter(lambda x:self.starttls_results[x]["starttls"],
                          self.starttls_results.keys())) > 0

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

    def get_dmarc_policy(self):
        # If the policy was never set, or isn't in the list of valid policies, check the parents.
        if self.dmarc_policy is None or self.dmarc_policy.lower() not in ["quarantine", "reject", "none"]:
            if self.base_domain is None:
                return ""
            else:
                return self.base_domain.get_dmarc_policy()
        return self.dmarc_policy


    def generate_results(self):
        mail_servers_that_are_listening = [x for x in self.starttls_results.keys() if self.starttls_results[x]["is_listening"]]
        mail_servers_that_support_smtp = [x for x in self.starttls_results.keys() if self.starttls_results[x]["supports_smtp"]]
        mail_servers_that_support_starttls = [x for x in self.starttls_results.keys() if self.starttls_results[x]["starttls"]]
        domain_supports_smtp = bool(mail_servers_that_support_starttls)
        
        results = {
            "Domain": self.domain_name,
            "Base Domain": self.base_domain_name,
            "Live": self.is_live,

            "MX Record": self.has_mail(),
            "Mail Servers": self.format_list(self.mail_servers),
            "Mail Server Ports Tested": self.format_list([str(port) for port in self.ports_tested]),
            "Domain Supports SMTP Results": self.format_list(mail_servers_that_support_smtp),
            # True if and only if at least one mail server speaks SMTP
            "Domain Supports SMTP": domain_supports_smtp,
            "Domain Supports STARTTLS Results": self.format_list(mail_servers_that_support_starttls),
            # True if and only if all mail servers that speak SMTP
            # also support STARTTLS
            "Domain Supports STARTTLS": domain_supports_smtp and all([self.starttls_results[x]["starttls"] for x in mail_servers_that_support_smtp]),

            "SPF Record": self.has_spf(),
            "Valid SPF": self.valid_spf,
            "SPF Results": self.format_list(self.spf),

            "DMARC Record": self.has_dmarc(),
            "Valid DMARC": self.has_dmarc() and self.valid_dmarc,
            "DMARC Results": self.format_list(self.dmarc),

            "DMARC Record on Base Domain": self.parent_has_dmarc(),
            "Valid DMARC Record on Base Domain": self.parent_has_dmarc() and self.parent_valid_dmarc(),
            "DMARC Results on Base Domain": self.parent_dmarc_results(),
            "DMARC Policy": self.get_dmarc_policy(),
            
            "Syntax Errors": self.format_list(self.syntax_errors)
            }

        return results

    # Format a list into a string to increase readability in CSV.
    def format_list(self, record_list):

        if not record_list:
            return ""

        return ", ".join(record_list)
