import csv
import logging
import requests
import smtplib
import spf
import datetime
import json
import socket

from DNS import dnslookup
from DNS import DNSError
import DNS

from trustymail.domain import Domain

CSV_HEADERS = [
    "Domain", "Base Domain", "Live",
    "MX Record", "Mail Servers", "Mail Server Ports Tested",
    "Domain Supports SMTP", "Domain Supports SMTP Results",
    "Domain Supports STARTTLS", "Domain Supports STARTTLS Results",
    "SPF Record", "Valid SPF", "SPF Results",
    "DMARC Record", "Valid DMARC", "DMARC Results",
    "DMARC Record on Base Domain", "Valid DMARC Record on Base Domain",
    "DMARC Results on Base Domain", "DMARC Policy",
    "Syntax Errors"
]

# A cache for SMTP scanning results
_SMTP_CACHE = {}


def domain_list_from_url(url):
    if not url:
        return []

    with requests.Session() as session:
        # Download current list of agencies, then let csv reader handle it.
        return domain_list_from_csv(session.get(url).content.decode('utf-8').splitlines())


def domain_list_from_csv(csv_file):
        domain_list = list(csv.reader(csv_file, delimiter=','))

        # Check the headers for the word domain - use that row.

        domain_column = 0

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
        for record in dnslookup(domain.domain_name, 'MX'):
            # Redirects will be presented as str of the redirect.
            if isinstance(record, tuple):
                domain.add_mx_record(record)
    except DNSError as error:
        handle_error("[MX]", domain, error)


def starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache):
    """
    Scan a domain to see if it supports SMTP and supports STARTTLS.

    Scan a domain to see if it supports SMTP.  If the domain does support
    SMTP, a further check will be done to see if it supports STARTTLS.
    All results are stored inside the Domain object that is passed in
    as a parameter.

    Parameters
    ----------
    domain : Domain
        The Domain to be tested.
        
    smtp_timeout : int
        The SMTP connection timeout in seconds.

    smtp_localhost : str
        The hostname to use when connecting to SMTP servers.

    smtp_ports : obj:`list` of :obj:`str`
        A comma-delimited list of ports at which to look for SMTP servers.  
        
    smtp_cache : bool
        Whether or not to cache SMTP results.
    """
    for mail_server in domain.mail_servers:
        for port in smtp_ports:
            domain.ports_tested.add(port)
            server_and_port = mail_server + ":" + str(port)

            if not smtp_cache or (server_and_port not in _SMTP_CACHE):
                domain.starttls_results[server_and_port] = {}
                
                smtp_connection = smtplib.SMTP(timeout=smtp_timeout,
                                               local_hostname=smtp_localhost)
                logging.debug("Testing " + server_and_port + " for STARTTLS support")
                # Try to connect.  This will tell us if something is
                # listening.
                try:
                    smtp_connection.connect(mail_server, port)
                    domain.starttls_results[server_and_port]["is_listening"] = True
                except (socket.timeout, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, ConnectionRefusedError, OSError) as error:
                    handle_error("[STARTTLS]", domain, error)
                    domain.starttls_results[server_and_port]["is_listening"] = False
                    domain.starttls_results[server_and_port]["supports_smtp"] = False
                    domain.starttls_results[server_and_port]["starttls"] = False

                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]
                    
                    continue

                # Now try to say hello.  This will tell us if the
                # thing that is listening is an SMTP server.
                try:
                    smtp_connection.ehlo_or_helo_if_needed()
                    domain.starttls_results[server_and_port]["supports_smtp"] = True
                    logging.debug("\t Supports SMTP")
                except (smtplib.SMTPHeloError, smtplib.SMTPServerDisconnected) as error:
                    handle_error("[STARTTLS]", domain, error)
                    domain.starttls_results[server_and_port]["supports_smtp"] = False
                    domain.starttls_results[server_and_port]["starttls"] = False
                    # smtplib freaks out if you call quit on a non-open
                    # connection
                    try:
                        smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected as error2:
                        handle_error("[STARTTLS]", domain, error2)
                        
                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]
                    
                    continue

                # Now check if the server supports STARTTLS.
                has_starttls = smtp_connection.has_extn("STARTTLS")
                domain.starttls_results[server_and_port]["starttls"] = has_starttls
                logging.debug("\t Supports STARTTLS: " + str(has_starttls))

                # Close the connection
                # smtplib freaks out if you call quit on a non-open
                # connection
                try:
                    smtp_connection.quit()
                except smtplib.SMTPServerDisconnected as error:
                    handle_error("[STARTTLS]", domain, error)

                # Copy the results into the cache, if necessary
                if smtp_cache:
                    _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]
            else:
                logging.debug("\tUsing cached results for " + server_and_port)
                # Copy the cached results into the domain object
                domain.starttls_results[server_and_port] = _SMTP_CACHE[server_and_port]

            
def spf_scan(domain):
    try:
        # for record in resolver.query(domain.domain_name, 'TXT'):
        for record in dnslookup(domain.domain_name, 'TXT'):

            record_text = record_to_str(record)

            if record_text.startswith("\""):
                record_text = record_text[1:-1]

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
                query = spf.query("127.0.0.1", "email_wizard@" + domain.domain_name, domain.domain_name, strict=2)
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
                domain.errors.append("Result Differs: Expected [{0}] - Actual [{1}]".format(result, response[0]))

    except DNSError as error:
        handle_error("[SPF]", domain, error)


def dmarc_scan(domain):
    # dmarc records are kept in TXT records for _dmarc.domain_name.
    try:
        dmarc_domain = '_dmarc.%s' % domain.domain_name
        for record in dnslookup(dmarc_domain, 'TXT'):

            record_text = record_to_str(record)

            if record_text.startswith("\""):
                record_text = record[1:-1]

            # Ensure the record is a DMARC record. Some domains that redirect will cause an SPF record to show.
            if record_text.startswith("v=DMARC1"):
                domain.dmarc.append(record_text)

            # Remove excess spacing
            record_text = record_text.strip(" ")

            # DMARC records follow a specific outline as to how they are defined - tag:value
            # We can split this up into a easily manipulatable
            tag_dict = {}
            for options in record_text.split(";"):
                if '=' not in options:
                    continue
                tag = options.split("=")[0].strip()
                value = options.split("=")[1].strip()
                tag_dict[tag] = value

            for tag in tag_dict:
                if tag not in ["v", "mailto", "rf", "p", "sp", "adkim", "aspf", "fo", "pct", "ri", "rua", "ruf"]:
                    logging.debug("\tWarning: Unknown DMARC mechanism {0}".format(tag))
                    domain.valid_dmarc = False
                elif tag == "p":
                    domain.dmarc_policy = tag_dict[tag]

    except DNSError as error:
        handle_error("[DMARC]", domain, error)


def find_host_from_ip(ip_addr):
    return DNS.revlookup(ip_addr)


def scan(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, scan_types):
    domain = Domain(domain_name)

    logging.debug("[{0}]".format(domain_name))

    DNS.defaults['timeout'] = timeout

    if scan_types["mx"] and domain.is_live:
        mx_scan(domain)

    if scan_types["starttls"] and domain.is_live:
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)

    if scan_types["spf"] and domain.is_live:
        spf_scan(domain)

    if scan_types["dmarc"] and domain.is_live:
        dmarc_scan(domain)

    # If the user didn't specify any scans then run a full scan.
    if domain.is_live and not (scan_types["mx"] or scan_types["starttls"]
                                   or scan_types["spf"] or scan_types["dmarc"]):
        mx_scan(domain)
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)
        spf_scan(domain)
        dmarc_scan(domain)

    return domain


def record_to_str(record):
    if isinstance(record, list):
        record = b''.join(record)

    if isinstance(record, bytes):
        record = record.decode('utf-8')

    return record


def handle_error(prefix, domain, error):
    if hasattr(error, "message"):
        if "NXDOMAIN" in error.message and prefix != "[DMARC]":
            domain.is_live = False
        domain.errors.append(error.message)
        logging.debug("  {0} {1}".format(prefix, error.message))
    else:
        domain.errors.append(str(error))
        logging.debug("  {0} {1}".format(prefix, str(error)))


def generate_csv(domains, file_name):
    output = open(file_name, 'w')
    writer = csv.writer(output)

    # First row should always be the headers
    writer.writerow(CSV_HEADERS)

    for domain in domains:
        row = []

        # Grab the dictionary for each row.
        # Keys for the dict are the column headers.
        results = domain.generate_results()

        for column in CSV_HEADERS:
            row.append(results[column])

        writer.writerow(row)

    output.close()


def generate_json(domains):
    output = []
    for domain in domains:
        output.append(domain.generate_results())

    return json.dumps(output, sort_keys=True,
                      indent=2, default=format_datetime)


# Taken from pshtt to keep formatting similar
def format_datetime(obj):
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, str):
        return obj
    else:
        return None
