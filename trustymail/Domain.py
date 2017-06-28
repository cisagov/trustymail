class Domain:

    def __init__(self, domain_name):
        self.domain_name = domain_name

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

    # Format a list into a string to increase readability in CSV.
    def format_list(self, record_list):

        if not record_list:
            return ""

        return ", ".join(record_list)

    def add_mx_record(self, record):
        self.mx_records.append(record)
        # Record in format "pref mail_server." Grab only address and remove trailing period.
        self.mail_servers.append(record.split(" ")[1][:-1])

    def generate_results(self):
        results = {
                        "Domain": self.domain_name,

                        "Sends Mail": self.has_mail(),
                        "SPF Record": self.has_spf(),
                        "DMARC Record": self.has_dmarc(),

                        "SPF Results": self.format_list(self.spf),
                        "DMARC Results": self.format_list(self.dmarc),
                        "Mail Servers": self.format_list(self.mail_servers),

                        "Valid SPF": self.valid_spf,
                        "Valid DMARC": self.valid_dmarc,

                        "Syntax Errors": self.format_list(self.syntax_errors)
                        # "Error Messages": self.format_list(self.errors)

                  }

        return results
