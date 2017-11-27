import csv
import datetime
import json
import logging
import re
import requests
import smtplib
import socket
import spf

import DNS
import dns.resolver
import dns.reversename

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
    "Syntax Errors", "Errors"
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


def mx_scan(resolver, domain):
    try:
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        for record in resolver.query(domain.domain_name, 'MX', tcp=True):
            domain.add_mx_record(record)
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
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


def check_spf_record(record_text, expected_result, domain):
    """
    Test to see if an SPF record is valid and correct.

    The record is tested by checking the response when we query if it
    allows us to send mail from an IP that is known not to be a mail
    server that appears in the MX records for ANY domain.

    Parameters
    ----------
    record_text : str
        The text of the SPF record to be tested.

    expected_result : str
        The expected result of the test.

    domain : trustymail.Domain
        The Domain object corresponding to the SPF record being
        tested.  Any errors will be logged to this object.
    """
    try:
        # Here I am using the IP address for c1b1.ncats.cyber.dhs.gov
        # (64.69.57.18) since it (1) has a valid PTR record and (2) is not
        # listed by anyone as a valid mail server.
        #
        # I'm actually temporarily using an IP that virginia.edu resolves to
        # until we resolve why Google DNS does not return the same PTR records
        # as the CAL DNS does for 64.69.57.18.
        query = spf.query("128.143.22.36", "email_wizard@" + domain.domain_name, domain.domain_name, strict=2)
        response = query.check()

        if response[0] == 'temperror':
            logging.debug(response[2])
        elif response[0] == 'permerror':
            logging.debug('\t' + response[2])
            domain.syntax_errors.append(response[2])
        elif response[0] == 'ambiguous':
            logging.debug('\t' + response[2])
            domain.syntax_errors.append(response[2])
        elif response[0] == expected_result:
            # Everything checks out the SPF syntax seems valid.
            domain.valid_spf = True
        else:
            domain.valid_spf = False
            logging.debug('\tResult Differs: Expected [{0}] - Actual [{1}]'.format(expected_result, response[0]))
            domain.errors.append('Result Differs: Expected [{0}] - Actual [{1}]'.format(expected_result, response[0]))
    except spf.AmbiguityWarning as error:
        logging.debug('\t' + error.msg)
        domain.syntax_errors.append(error.msg)


def get_spf_record_text(resolver, domain_name, domain, follow_redirect=False):
    """
    Get the SPF record text for the given domain name.

    DNS queries are performed using the dns.resolver.Resolver object.
    Errors are logged to the trustymail.Domain object.  The Boolean
    parameter indicates whether to follow redirects in SPF records.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        The Resolver object to use for DNS queries.

    domain_name : str
        The domain name to query for an SPF record.

    domain : trustymail.Domain
        The Domain object whose corresponding SPF record text is
        desired.  Any errors will be logged to this object.

    follow_redirect : bool
       A Boolean value indicating whether to follow redirects in SPF
       records.

    Returns
    -------
    str: The desired SPF record text
    """
    record_to_return = None
    try:
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        for record in resolver.query(domain_name, 'TXT', tcp=True):
            record_text = record.to_text().strip('"')

            if not record_text.startswith('v=spf1'):
                # Not an spf record, ignore it.
                continue

            match = re.search('v=spf1\s*redirect=(\S*)', record_text)
            if follow_redirect and match:
                redirect_domain_name = match.group(1)
                record_to_return = get_spf_record_text(resolver, redirect_domain_name, domain)
            else:
                record_to_return = record_text
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
        handle_error('[SPF]', domain, error)

    return record_to_return


def spf_scan(resolver, domain):
    """
    Scan a domain to see if it supports SPF.  If the domain has an SPF
    record, verify that it properly rejects mail sent from an IP known
    to be disallowed.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        The Resolver object to use for DNS queries.

    domain : trustymail.Domain
        The Domain object being scanned for SPF support.  Any errors
        will be logged to this object.
    """
    # If an SPF record exists, record the raw SPF record text in the
    # Domain object
    record_text_not_following_redirect = get_spf_record_text(resolver, domain.domain_name, domain)
    if record_text_not_following_redirect:
        domain.spf.append(record_text_not_following_redirect)

    record_text_following_redirect = get_spf_record_text(resolver, domain.domain_name, domain, True)
    if record_text_following_redirect:
        # From the found record grab the specific result when something
        # doesn't match.  Definitions of result come from
        # https://www.ietf.org/rfc/rfc4408.txt
        if record_text_following_redirect.endswith('-all'):
            result = 'fail'
        elif record_text_following_redirect.endswith('?all'):
            result = 'neutral'
        elif record_text_following_redirect.endswith('~all'):
            result = 'softfail'
        elif record_text_following_redirect.endswith('all') or record_text_following_redirect.endswith('+all'):
            result = 'pass'
        else:
            result = 'neutral'

        check_spf_record(record_text_not_following_redirect, result, domain)


def dmarc_scan(resolver, domain):
    # dmarc records are kept in TXT records for _dmarc.domain_name.
    try:
        dmarc_domain = '_dmarc.%s' % domain.domain_name
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        for record in resolver.query(dmarc_domain, 'TXT', tcp=True):
            record_text = record.to_text().strip('"')

            # Ensure the record is a DMARC record. Some domains that
            # redirect will cause an SPF record to show.
            if record_text.startswith("v=DMARC1"):
                domain.dmarc.append(record_text)

            # Remove excess whitespace
            record_text = record_text.strip()

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

    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as error:
        handle_error("[DMARC]", domain, error)


def find_host_from_ip(resolver, ip_addr):
    # Use TCP, since we care about the content and correctness of the records
    # more than whether their records fit in a single UDP packet.
    hostname, _ = resolver.query(dns.reversename.from_address(ip_addr), "PTR", tcp=True)
    return str(hostname)


def scan(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, scan_types, dns_hostnames):
    #
    # Configure the dnspython library
    #

    # Set some timeouts
    dns.resolver.timeout = float(timeout)
    dns.resolver.lifetime = float(timeout)

    # Our resolver
    #
    # Note that it uses the system configuration in /etc/resolv.conf
    # if no DNS hostnames are specified.
    resolver = dns.resolver.Resolver(configure=not dns_hostnames)
    # Retry queries if we receive a SERVFAIL response.  This may only indicate
    # a temporary network problem.
    resolver.retry_servfail = True
    # If the user passed in DNS hostnames to query against then use them
    if dns_hostnames:
        resolver.nameservers = dns_hostnames

    #
    # The spf library uses py3dns behind the scenes, so we need to configure
    # that too
    #
    DNS.defaults['timeout'] = timeout
    # Use TCP instead of UDP
    DNS.defaults['protocol'] = 'tcp'
    # If the user passed in DNS hostnames to query against then use them
    if dns_hostnames:
        DNS.defaults['server'] = dns_hostnames

    # Domain's constructor needs all these parameters because it does a DMARC
    # scan in its init
    domain = Domain(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, dns_hostnames)

    logging.debug("[{0}]".format(domain_name.lower()))

    if scan_types["mx"] and domain.is_live:
        mx_scan(resolver, domain)

    if scan_types["starttls"] and domain.is_live:
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)

    if scan_types["spf"] and domain.is_live:
        spf_scan(resolver, domain)

    if scan_types["dmarc"] and domain.is_live:
        dmarc_scan(resolver, domain)

    # If the user didn't specify any scans then run a full scan.
    if domain.is_live and not (scan_types["mx"] or scan_types["starttls"] or scan_types["spf"] or scan_types["dmarc"]):
        mx_scan(resolver, domain)
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)
        spf_scan(resolver, domain)
        dmarc_scan(resolver, domain)

    return domain


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
