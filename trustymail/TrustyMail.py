import csv
import logging

import dns.resolver
import requests
import spf
from dns import reversename

from trustymail.Domain import Domain

CSV_HEADERS = [
    "Domain", "Base Domain",
    "Sends Mail", "Mail Servers",
    "SPF Record", "DMARC Record",
    "DMARC Results", "SPF Results",
    "Valid SPF", "Valid DMARC",
    "Syntax Errors"
]


def domain_list_from_url(url):
    if not url:
        return []

    with requests.Session() as session:
        # Download current list of agencies, then let csv reader handle it.
        return domain_list_from_csv(session.get(url).content.decode('utf-8').splitlines())


def domain_list_from_csv(csv_file):
        domain_list = list(csv.reader(csv_file, delimiter=','))

        # Check the headers for the word domain - use that row.

        domain_column = 0;

        for i in range(0, len(domain_list[0])):
            header = domain_list[0][i]
            if "domain" in header.lower():
                domain_column = i
                # CSV starts with headers, remove first row.
                domain_list.pop(0)
                break

        domains = []
        for row in domain_list:
            domains.append(row[domain_column])

        return domains


def mx_scan(domain):
    try:
        for record in resolver.query(domain.domain_name, 'MX'):
            domain.add_mx_record(record.to_text())

    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
            domain.errors.append(str(error))


def spf_scan(domain):
    try:
        for record in resolver.query(domain.domain_name, 'TXT'):
            # Sometimes .to_text() with give '"record_info"' so need to remove excess quotes
            if record.to_text().startswith("\""):
                record_text = record.to_text()[1:-1]
            else:
                record_text = record.to_text()

            if not record_text.startswith("v=spf1"):
                # Not an spf record, ignore it.
                continue

            domain.spf.append(record_text)

            # From the found record grab the specific result when something doesn't match.
            # Definitions of result come from https://www.ietf.org/rfc/rfc4408.txt
            if record_text.endswith("-all"):
                result = 'fail'
            elif record_text.endswith("?all"):
                result = "neutral"
            elif record_text.endswith("~all"):
                result = "softfail"
            elif record_text.endswith("all") or record_text.endswith("+all"):
                result = "pass"
            else:
                result = "neutral"

            try:
                query = spf.query('127.0.0.1', "email_wizard@" + domain.domain_name, domain.domain_name, strict=2)
                response = query.check()
            except spf.AmbiguityWarning as error:
                logging.debug("\t" + error.msg)
                domain.syntax_errors.append(error.msg)
                continue

            if response[0] == 'temperror':
                logging.debug(response[2])
            elif response[0] == 'permerror':
                logging.debug("\t" + response[2])
                domain.syntax_errors.append(response[2])
            elif response[0] == 'ambiguous':
                logging.debug("\t" + response[2])
                domain.syntax_errors.append(response[2])
            elif response[0] == result:
                # Everything checks out the SPF syntax seems valid.
                domain.valid_spf = True
                continue
            else:
                domain.valid_spf = False
                logging.debug("\tResult Differs: Expected [{0}] - Actual [{1}]".format(result, response[0]))

    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
        logging.debug("\tError: {0}".format(str(error)))
        domain.errors.append(str(error))


def dmarc_scan(domain):
    # dmarc records are kept in TXT records for _dmarc.domain_name.
    try:
        dmarc_domain = '_dmarc.%s' % domain.domain_name
        for record in resolver.query(dmarc_domain, 'TXT'):

            if record.to_text().startswith("\""):
                record_text = record.to_text()[1:-1]
            else:
                record_text = record.to_text()

            # Ensure the record is a DMARC record. Some domains that redirect will cause an SPF record to show.
            if record_text.startswith("v=DMARC1"):
                domain.dmarc.append(record_text)

            # Remove excess spacing
            record_text = record_text.strip(" ")

            # DMARC records follow a specific outline as to how they are defined - tag:value
            # We can split this up into a easily manipulatable
            tag_dict = {}
            for options in record_text.split(";"):
                tag = options.split("=")[0].strip()
                value = options.split("=")[1].strip()
                tag_dict[tag] = value

            for tag in [tag.split("=") for tag in record_text.split(";") if tag]:
                if tag not in ["v", "mailto", "rf", "p", "sp", "adkim", "aspf", "fo", "pct", "ri", "rua", "ruf"]:
                    pass
                    # It's fine, nothing to see here.
                else:
                    pass
                    # Mechanic doesn't exist, RFC says to ignore it, so is this an issue?

    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
        domain.errors.append(str(error))


def find_host_from_ip(ip_addr):
    return str(resolver.query(reversename.from_address(ip_addr), "PTR")[0])


def scan(domain_name, timeout, scan_types):
    domain = Domain(domain_name)

    logging.debug("[{0}]".format(domain_name))

    resolver.timeout = resolver.lifetime = timeout

    if scan_types["mx"]:
        mx_scan(domain)

    if scan_types["spf"]:
        spf_scan(domain)

    if scan_types["dmarc"]:
        dmarc_scan(domain)

    # If the user didn't specify any scans then run a full scan.
    if not (scan_types["mx"] or scan_types["spf"] or scan_types["dmarc"]):
        mx_scan(domain)
        spf_scan(domain)
        dmarc_scan(domain)

    return domain


def generate_csv(domains, file_name):
    output = open(file_name, 'w')
    writer = csv.writer(output)

    writer.writerow(CSV_HEADERS)

    for domain in domains:
        row = []

        results = domain.generate_results()

        for column in CSV_HEADERS:
            row.append(results[column])

        writer.writerow(row)

    output.close()


# Default resolver settings
resolver = dns.resolver.Resolver()
