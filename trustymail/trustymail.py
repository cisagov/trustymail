import csv
import datetime
import inspect
import json
import logging
import re
from collections import OrderedDict
import requests
import smtplib
import socket
import spf

import DNS
import dns.resolver
import dns.reversename


from trustymail.domain import get_public_suffix, Domain

# A cache for SMTP scanning results
_SMTP_CACHE = {}

MAILTO_REGEX = re.compile(r"(mailto):([\w\-!#$%&'*+-/=?^_`{|}~][\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?")


def domain_list_from_url(url):
    if not url:
        return []

    with requests.Session() as session:
        # Download current list of agencies, then let csv reader handle it.
        return domain_list_from_csv(session.get(url).content.decode('utf-8').splitlines())


def domain_list_from_csv(csv_file):
    domain_list = list(csv.reader(csv_file, delimiter=','))

    # Check the headers for the word domain - use that column.

    domain_column = 0

    for i in range(0, len(domain_list[0])):
        header = domain_list[0][i]
        if 'domain' in header.lower():
            domain_column = i
            # CSV starts with headers, remove first row.
            domain_list.pop(0)
            break

    domains = []
    for row in domain_list:
        if row is not None and len(row) > 0:
            domains.append(row[domain_column])

    return domains


def check_dnssec(domain, domain_name, record_type):
    """Checks whether the domain has a record of type that is protected
    by DNSSEC or NXDOMAIN or NoAnswer that is protected by DNSSEC.

    TODO: Probably does not follow redirects (CNAMEs).  Should work on
    that in the future.
    """
    try:
        query = dns.message.make_query(domain_name, record_type, want_dnssec=True)
        for nameserver in DNS_RESOLVERS:
            response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
            if response is not None:
                if response.flags & dns.flags.AD:
                    return True
                else:
                    return False
    except Exception as error:
        handle_error('[MX DNSSEC]', domain, error)
        return None


def mx_scan(resolver, domain):
    try:
        if domain.mx_records is None:
            domain.mx_records = []
        if domain.mail_servers is None:
            domain.mail_servers = []
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        for record in resolver.query(domain.domain_name, 'MX', tcp=True):
            domain.add_mx_record(record)
        domain.mx_records_dnssec = check_dnssec(domain, domain.domain_name, 'MX')
    except (dns.resolver.NoNameservers) as error:
        # The NoNameServers exception means that we got a SERVFAIL response.
        # These responses are almost always permanent, not temporary, so let's
        # treat the domain as not live.
        domain.is_live = False
        handle_error('[MX]', domain, error)
    except dns.resolver.NXDOMAIN as error:
        domain.is_live = False
        # NXDOMAIN can still have DNSSEC
        domain.mx_records_dnssec = check_dnssec(domain, domain.domain_name, 'MX')
        handle_error('[MX]', domain, error)
    except (dns.resolver.NoAnswer) as error:
        # The NoAnswer exception means that the domain does exist in
        # DNS, but it does not have any MX records.  It sort of makes
        # sense to treat this case as "not live", but @h-m-f-t
        # (Cameron Dixon) points out that "a domain not NXDOMAINing
        # or SERVFAILing is a reasonable proxy for existence. It's
        # functionally "live" if the domain resolves in public DNS,
        # and therefore can benefit from DMARC action."
        #
        # See also https://github.com/cisagov/trustymail/pull/91

        # NoAnswer can still have DNSSEC
        domain.mx_records_dnssec = check_dnssec(domain, domain.domain_name, 'MX')
        handle_error('[MX]', domain, error)
    except dns.exception.Timeout as error:
        domain.mx_records_dnssec = check_dnssec(domain, domain.domain_name, 'MX')
        handle_error('[MX]', domain, error)


def starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache):
    """Scan a domain to see if it supports SMTP and supports STARTTLS.

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
            server_and_port = mail_server + ':' + str(port)

            if not smtp_cache or (server_and_port not in _SMTP_CACHE):
                domain.starttls_results[server_and_port] = {}

                smtp_connection = smtplib.SMTP(timeout=smtp_timeout,
                                               local_hostname=smtp_localhost)
                # The following line is useful when debugging why an
                # SMTP connection fails.  It prints out all the
                # traffic sent to and from the SMTP server.
                smtp_connection.set_debuglevel(1)
                logging.debug('Testing ' + server_and_port + ' for STARTTLS support')

                # Look up the IPv4 address for mail_server.
                #
                # By default, smtplib looks for A and AAAA records
                # from DNS and uses the first one that it can connect
                # to.  What I find when running in Lambda (at least in
                # my VPC that doesn't support IPv6) is that when DNS
                # returns IPv6 an address I get a low level "errno 97
                # - Address family not supported by protocol" error
                # and the other addresses returned by DNS are not
                # tried.  Therefore the hostname is not scanned at
                # all.
                #
                # To get around this I look up the A record and use
                # that instead of the hostname in DNS when I call
                # smtp_connection.connect().
                addr_info = socket.getaddrinfo(
                    mail_server, port, socket.AF_INET, socket.SOCK_STREAM
                )
                socket_address = addr_info[0][4]
                mail_server_ip_address = socket_address[0]

                # Try to connect.  This will tell us if something is
                # listening.
                try:
                    smtp_connection.connect(mail_server_ip_address, port)
                    domain.starttls_results[server_and_port]['is_listening'] = True
                except (socket.timeout, smtplib.SMTPConnectError,
                        smtplib.SMTPServerDisconnected,
                        ConnectionRefusedError, OSError) as error:
                    handle_error('[STARTTLS]', domain, error)
                    domain.starttls_results[server_and_port]['is_listening'] = False
                    domain.starttls_results[server_and_port]['supports_smtp'] = False
                    domain.starttls_results[server_and_port]['starttls'] = False

                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]

                    continue

                # Now try to say hello.  This will tell us if the
                # thing that is listening is an SMTP server.
                try:
                    smtp_connection.ehlo_or_helo_if_needed()
                    domain.starttls_results[server_and_port]['supports_smtp'] = True
                    logging.debug('\t Supports SMTP')
                except (smtplib.SMTPHeloError, smtplib.SMTPServerDisconnected) as error:
                    handle_error('[STARTTLS]', domain, error)
                    domain.starttls_results[server_and_port]['supports_smtp'] = False
                    domain.starttls_results[server_and_port]['starttls'] = False
                    # smtplib freaks out if you call quit on a non-open
                    # connection
                    try:
                        smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected as error2:
                        handle_error('[STARTTLS]', domain, error2)

                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]

                    continue

                # Now check if the server supports STARTTLS.
                has_starttls = smtp_connection.has_extn('STARTTLS')
                domain.starttls_results[server_and_port]['starttls'] = has_starttls
                logging.debug('\t Supports STARTTLS: ' + str(has_starttls))

                # Close the connection
                # smtplib freaks out if you call quit on a non-open
                # connection
                try:
                    smtp_connection.quit()
                except smtplib.SMTPServerDisconnected as error:
                    handle_error('[STARTTLS]', domain, error)

                # Copy the results into the cache, if necessary
                if smtp_cache:
                    _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]
            else:
                logging.debug('\tUsing cached results for ' + server_and_port)
                # Copy the cached results into the domain object
                domain.starttls_results[server_and_port] = _SMTP_CACHE[server_and_port]


def check_spf_record(record_text, domain, strict=2):
    """Test to see if an SPF record is valid and correct.

    The record is tested by evaluating the response when we query
    using an IP that is known not to be a mail server that appears in
    the MX records for ANY domain.

    Parameters
    ----------
    record_text : str
        The text of the SPF record to be tested.

    domain : trustymail.Domain
        The Domain object corresponding to the SPF record being
        tested.  Any errors will be logged to this object.

    strict : bool or int
        The level of strictness to use when verifying an SPF record.
        Valid values are True, False, and 2.  The last value is the
        most harsh.

    """
    try:
        # Here I am using the IP address for
        # ec2-100-27-42-254.compute-1.amazonaws.com (100.27.42.254)
        # since it (1) has a valid PTR record and (2) is not listed by
        # anyone as a valid mail server.  (The second item follows
        # from the fact that AWS has semi-permanently assigned this IP
        # to NCATS as part of our contiguous netblock, and we are not
        # using it as a mail server or including it as an MX record
        # for any domain.)
        #
        # Passing verbose=True causes the SPF library being used to
        # print out the SPF records encountered as include and
        # redirect cause other SPF records to be looked up.
        query = spf.query('100.27.42.254',
                          'email_wizard@' + domain.domain_name,
                          domain.domain_name, strict=strict, verbose=True)
        response = query.check(spf=record_text)

        response_type = response[0]
        # A value of none means that no valid SPF record was obtained
        # from DNS.  We get this result when we get an ambiguous
        # result because of an SPF record with incorrect syntax, then
        # rerun check_spf_record() with strict=True (instead of 2).
        if response_type == 'temperror' or response_type == 'permerror' \
           or response_type == 'none':
            domain.valid_spf = False
            handle_error('[SPF]', domain,
                         'SPF query returned {}: {}'.format(response_type,
                                                            response[2]))
        elif response_type == 'ambiguous':
            # Log the ambiguity so it appears in the results CSV
            handle_error('[SPF]', domain,
                         'SPF query returned {}: {}'.format(response_type,
                                                            response[2]))

            # Now rerun the check with less strictness to get an
            # actual result.  (With strict=2, the SPF library stops
            # processing once it encounters an AmbiguityWarning.)
            check_spf_record(record_text, domain, True)
        else:
            # Everything checks out.  The SPF syntax seems valid.
            domain.valid_spf = True
    except spf.AmbiguityWarning as error:
        domain.valid_spf = False
        handle_error('[SPF]', domain, error)


def get_spf_record_text(resolver, domain_name, domain, follow_redirect=False):
    """Get the SPF record text for the given domain name.

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
            record_text = remove_quotes(record.to_text())

            if not record_text.startswith('v=spf1'):
                # Not an spf record, ignore it.
                continue

            match = re.search(r'v=spf1\s*redirect=(\S*)', record_text)
            if follow_redirect and match:
                redirect_domain_name = match.group(1)
                record_to_return = get_spf_record_text(resolver,
                                                       redirect_domain_name,
                                                       domain)
            else:
                record_to_return = record_text

        domain.spf_dnssec = check_dnssec(domain, domain.domain_name, 'TXT')
    except (dns.resolver.NoNameservers) as error:
        # The NoNameservers exception means that we got a SERVFAIL response.
        # These responses are almost always permanent, not temporary, so let's
        # treat the domain as not live.
        domain.is_live = False
        handle_error('[SPF]', domain, error)
    except (dns.resolver.NXDOMAIN) as error:
        domain.is_live = False
        domain.spf_dnssec = check_dnssec(domain, domain.domain_name, 'TXT')
        handle_error('[SPF]', domain, error)
    except (dns.resolver.NoAnswer) as error:
        domain.spf_dnssec = check_dnssec(domain, domain.domain_name, 'TXT')
        handle_error('[SPF]', domain, error)
    except (dns.exception.Timeout) as error:
        domain.spf_dnssec = check_dnssec(domain, domain.domain_name, 'TXT')
        handle_error('[SPF]', domain, error)
    return record_to_return


def spf_scan(resolver, domain):
    """Scan a domain to see if it supports SPF.  If the domain has an SPF
    record, verify that it properly handles mail sent from an IP known
    not to be listed in an MX record for ANY domain.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        The Resolver object to use for DNS queries.

    domain : trustymail.Domain
        The Domain object being scanned for SPF support.  Any errors
        will be logged to this object.

    """
    if domain.spf is None:
        domain.spf = []

    # If an SPF record exists, record the raw SPF record text in the
    # Domain object
    record_text_not_following_redirect = get_spf_record_text(resolver,
                                                             domain.domain_name,
                                                             domain)
    if record_text_not_following_redirect:
        domain.spf.append(record_text_not_following_redirect)

    record_text_following_redirect = get_spf_record_text(resolver,
                                                         domain.domain_name,
                                                         domain,
                                                         True)
    if record_text_following_redirect:
        check_spf_record(record_text_following_redirect, domain)


def parse_dmarc_report_uri(uri):
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf)`` URI

    Notes
    -----
        ``mailto:`` is the only reporting URI supported in `DMARC1`

    Arguments
    ---------
        uri: A DMARC URI

    Returns
    -------
        OrderedDict: Keys: ''scheme`` ``address`` and ``size_limit``

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        return None
    match = mailto_matches[0]
    scheme = match[0]
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return OrderedDict([("scheme", scheme), ("address", email_address), ("size_limit", size_limit)])


def dmarc_scan(resolver, domain):
    # dmarc records are kept in TXT records for _dmarc.domain_name.
    try:
        if domain.dmarc is None:
            domain.dmarc = []
        dmarc_domain = '_dmarc.%s' % domain.domain_name
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        all_records = resolver.query(dmarc_domain, 'TXT', tcp=True)
        domain.dmarc_dnssec = check_dnssec(domain, dmarc_domain, 'TXT')
        # According to step 4 in section 6.6.3 of the RFC
        # (https://tools.ietf.org/html/rfc7489#section-6.6.3), "Records that do
        # not start with a "v=" tag that identifies the current version of
        # DMARC are discarded."
        records = [record for record in all_records if record.to_text().startswith('"v=DMARC1;')]

        # Treat multiple DMARC records as an error, in accordance with the RFC
        # (https://tools.ietf.org/html/rfc7489#section-6.6.3)
        if len(records) > 1:
            handle_error('[DMARC]', domain, 'Warning: Multiple DMARC records present')
            domain.valid_dmarc = False
        elif records:
            record = records[0]

            record_text = remove_quotes(record.to_text())

            # Ensure the record is a DMARC record. Some domains that
            # redirect will cause an SPF record to show.
            if record_text.startswith('v=DMARC1'):
                domain.dmarc.append(record_text)
            elif record_text.startswith('v=spf1'):
                msg = "Found a SPF record where a DMARC record should be; most likely, the _dmarc " \
                      "subdomain record does not actually exist, and the request for TXT records was " \
                      "redirected to the base domain"
                handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                domain.valid_dmarc = False

            # Remove excess whitespace
            record_text = record_text.strip()

            # DMARC records follow a specific outline as to how they are
            # defined - tag:value We can split this up into a easily
            # manipulatable dictionary
            tag_dict = {}
            for options in record_text.split(';'):
                if '=' not in options:
                    continue
                tag = options.split('=')[0].strip()
                value = options.split('=')[1].strip()
                tag_dict[tag] = value

            # Before we set sp=p if it is not explicitly contained in
            # the DMARC record, log a warning if it is explicitly set
            # for a subdomain of an organizational domain.
            if 'sp' in tag_dict and not domain.is_base_domain:
                handle_error('[DMARC]', domain, 'Warning: The sp tag will be ignored for DMARC records published on subdomains. See here for details:  https://tools.ietf.org/html/rfc7489#section-6.3.', syntax_error=False)
            if 'p' not in tag_dict:
                msg = 'Record missing required policy (p) tag'
                handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                domain.valid_dmarc = False
            elif 'sp' not in tag_dict:
                tag_dict['sp'] = tag_dict['p']
            if 'ri' not in tag_dict:
                tag_dict['ri'] = 86400
            if 'pct' not in tag_dict:
                tag_dict['pct'] = 100
            if 'adkim' not in tag_dict:
                tag_dict['adkim'] = 'r'
            if 'aspf' not in tag_dict:
                tag_dict['aspf'] = 'r'
            if 'fo' not in tag_dict:
                tag_dict['fo'] = '0'
            if 'rf' not in tag_dict:
                tag_dict['rf'] = 'afrf'
            if 'rua' not in tag_dict:
                domain.dmarc_has_aggregate_uri = False
            if 'ruf' not in tag_dict:
                domain.dmarc_has_forensic_uri = False

            for tag in tag_dict:
                if tag not in ['v', 'mailto', 'rf', 'p', 'sp', 'adkim', 'aspf', 'fo', 'pct', 'ri', 'rua', 'ruf']:
                    msg = 'Unknown DMARC tag {0}'.format(tag)
                    handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                    domain.valid_dmarc = False
                elif tag == 'p':
                    if tag_dict[tag] not in ['none', 'quarantine', 'reject']:
                        msg = 'Unknown DMARC policy {0}'.format(tag)
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                    else:
                        domain.dmarc_policy = tag_dict[tag]
                elif tag == 'sp':
                    if tag_dict[tag] not in ['none', 'quarantine', 'reject']:
                        msg = 'Unknown DMARC subdomain policy {0}'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                    else:
                        domain.dmarc_subdomain_policy = tag_dict[tag]
                elif tag == 'fo':
                    values = tag_dict[tag].split(':')
                    if '0' in values and '1' in values:
                        msg = 'fo tag values 0 and 1 are mutually exclusive'
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                    for value in values:
                        if value not in ['0', '1', 'd', 's']:
                            msg = 'Unknown DMARC fo tag value {0}'.format(value)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                elif tag == 'rf':
                    values = tag_dict[tag].split(':')
                    for value in values:
                        if value not in ['afrf']:
                            msg = 'Unknown DMARC rf tag value {0}'.format(value)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                elif tag == 'ri':
                    try:
                        int(tag_dict[tag])
                    except ValueError:
                        msg = 'Invalid DMARC ri tag value: {0} - must be an integer'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                elif tag == 'pct':
                    try:
                        pct = int(tag_dict[tag])
                        if pct < 0 or pct > 100:
                            msg = 'Error: invalid DMARC pct tag value: {0} - must be an integer between ' \
                                  '0 and 100'.format(tag_dict[tag])
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                        domain.dmarc_pct = pct
                        if pct < 100:
                            handle_syntax_error('[DMARC]', domain, 'Warning: The DMARC pct tag value may be less than 100 (the implicit default) during deployment, but should be removed or set to 100 upon full deployment')
                    except ValueError:
                        msg = 'invalid DMARC pct tag value: {0} - must be an integer'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                elif tag == 'rua' or tag == 'ruf':
                    uris = tag_dict[tag].split(',')
                    if len(uris) > 2:
                        handle_error('[DMARC]', domain, 'Warning: The {} tag specifies {} URIs.  Receivers are not required to send reports to more than two URIs - https://tools.ietf.org/html/rfc7489#section-6.2.'.format(tag, len(uris)), syntax_error=False)
                    for uri in uris:
                        # mailto: is currently the only type of DMARC URI
                        parsed_uri = parse_dmarc_report_uri(uri)
                        if parsed_uri is None:
                            msg = 'Error: {0} is an invalid DMARC URI'.format(uri)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                        else:
                            if tag == "rua":
                                domain.dmarc_aggregate_uris.append(uri)
                            elif tag == "ruf":
                                domain.dmarc_forensic_uris.append(uri)
                            email_address = parsed_uri["address"]
                            email_domain = email_address.split('@')[-1]
                            if get_public_suffix(email_domain).lower() != domain.base_domain_name.lower():
                                target = '{0}._report._dmarc.{1}'.format(domain.domain_name, email_domain)
                                error_message = '{0} does not indicate that it accepts DMARC reports about {1} - ' \
                                                'https://tools.ietf.org' \
                                                '/html/rfc7489#section-7.1'.format(email_domain,
                                                                                   domain.domain_name)
                                try:
                                    answer = remove_quotes(resolver.query(target, 'TXT', tcp=True)[0].to_text())
                                    if not answer.startswith('v=DMARC1'):
                                        handle_error('[DMARC]', domain, '{0}'.format(error_message))
                                        domain.dmarc_reports_address_error = True
                                        domain.valid_dmarc = False
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                                    handle_syntax_error('[DMARC]', domain, '{0}'.format(error_message))
                                    domain.dmarc_reports_address_error = True
                                    domain.valid_dmarc = False
                                try:
                                    # Ensure ruf/rua/email domains have MX records
                                    resolver.query(email_domain, 'MX', tcp=True)
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                                    handle_syntax_error('[DMARC]', domain, 'The domain for reporting '
                                                                           'address {0} does not have any '
                                                                           'MX records'.format(email_address))
                                    domain.valid_dmarc = False

            # Log a warning if the DMARC record specifies a policy but does not
            # specify any ruf or rua URIs, since this greatly reduces the
            # usefulness of DMARC.
            if 'p' in tag_dict and 'rua' not in tag_dict and 'ruf' not in tag_dict:
                handle_syntax_error('[DMARC]', domain, 'Warning: A DMARC policy is specified but no reporting URIs.  This makes the DMARC implementation considerably less useful than it could be.  See https://tools.ietf.org/html/rfc7489#section-6.5 for more details.')

        domain.dmarc_has_aggregate_uri = len(domain.dmarc_aggregate_uris) > 0
        domain.dmarc_has_forensic_uri = len(domain.dmarc_forensic_uris) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as error:
        domain.dmarc_dnssec = check_dnssec(domain, dmarc_domain, 'TXT')
        handle_error('[DMARC]', domain, error)
    except (dns.resolver.NoNameservers) as error:
        # Normally we count a NoNameservers exception as indicating
        # that a domain is "not live".  In this case we don't, though,
        # since the DMARC DNS check doesn't query for the domain name
        # itself.  If the domain name is domain.com, the DMARC DNS
        # check queries for _dmarc.domain.com.
        handle_error('[DMARC]', domain, error)


def find_host_from_ip(resolver, ip_addr):
    # Use TCP, since we care about the content and correctness of the records
    # more than whether their records fit in a single UDP packet.
    hostname, _ = resolver.query(dns.reversename.from_address(ip_addr), 'PTR', tcp=True)
    return str(hostname)


def scan(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, scan_types, dns_hostnames):
    #
    # Configure the dnspython library
    #
    global DNS_TIMEOUT, DNS_RESOLVERS

    # Our resolver
    #
    # Note that it uses the system configuration in /etc/resolv.conf
    # if no DNS hostnames are specified.
    resolver = dns.resolver.Resolver(configure=not dns_hostnames)
    # This is a setting that controls whether we retry DNS servers if
    # we receive a SERVFAIL response from them.  We set this to False
    # because, unless the reason for the SERVFAIL is truly temporary
    # and resolves before trustymail finishes scanning the domain,
    # this can obscure the potentially informative SERVFAIL error as a
    # DNS timeout because of the way dns.resolver.query() is written.
    # See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query.
    resolver.retry_servfail = False
    # Set some timeouts.  The timeout should be less than or equal to
    # the lifetime, but longer than the time a DNS server takes to
    # return a SERVFAIL (since otherwise it's possible to get a DNS
    # timeout when you should be getting a SERVFAIL.)  See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query
    # and
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver._compute_timeout.
    resolver.timeout = float(timeout)
    resolver.lifetime = float(timeout)
    DNS_TIMEOUT = timeout
    # If the user passed in DNS hostnames to query against then use them
    if dns_hostnames:
        resolver.nameservers = dns_hostnames
        DNS_RESOLVERS = dns_hostnames
    else:
        DNS_RESOLVERS = resolver.nameservers

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

    logging.debug('[{0}]'.format(domain_name.lower()))

    if scan_types['mx'] and domain.is_live:
        mx_scan(resolver, domain)

    if scan_types['starttls'] and domain.is_live:
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)

    if scan_types['spf'] and domain.is_live:
        spf_scan(resolver, domain)

    if scan_types['dmarc'] and domain.is_live:
        dmarc_scan(resolver, domain)

    # If the user didn't specify any scans then run a full scan.
    if domain.is_live and not (scan_types['mx'] or scan_types['starttls'] or scan_types['spf'] or scan_types['dmarc']):
        mx_scan(resolver, domain)
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)
        spf_scan(resolver, domain)
        dmarc_scan(resolver, domain)

    return domain


def handle_error(prefix, domain, error, syntax_error=False):
    """Handle an error by logging via the Python logging library and
    recording it in the debug_info or syntax_error members of the
    trustymail.Domain object.

    Since the "Debug Info" and "Syntax Error" fields in the CSV output
    of trustymail come directly from the debug_info and syntax_error
    members of the trustymail.Domain object, and that CSV is likely
    all we will have to reconstruct how trustymail reached the
    conclusions it did, it is vital to record as much helpful
    information as possible.

    Parameters
    ----------
    prefix : str
        The prefix to use when constructing the log string.  This is
        usually the type of trustymail test that was being performed
        when the error condition occurred.

    domain : trustymail.Domain
        The Domain object in which the error or syntax error should be
        recorded.

    error : str, BaseException, or Exception
        Either a string describing the error, or an exception object
        representing the error.

    syntax_error : bool
        If True then the error will be recorded in the syntax_error
        member of the trustymail.Domain object.  Otherwise it is
        recorded in the error member of the trustymail.Domain object.
    """
    # Get the previous frame in the stack - the one that is calling
    # this function
    frame = inspect.currentframe().f_back
    function = frame.f_code
    function_name = function.co_name
    filename = function.co_filename
    line = frame.f_lineno

    error_template = '{prefix} In {function_name} at {filename}:{line}: {error}'

    if hasattr(error, 'message'):
        if syntax_error and 'NXDOMAIN' in error.message and prefix != '[DMARC]':
            domain.is_live = False
        error_string = error_template.format(prefix=prefix, function_name=function_name, line=line, filename=filename,
                                             error=error.message)
    else:
        error_string = error_template.format(prefix=prefix, function_name=function_name, line=line, filename=filename,
                                             error=str(error))

    if syntax_error:
        domain.syntax_errors.append(error_string)
    else:
        domain.debug_info.append(error_string)
    logging.debug(error_string)


def handle_syntax_error(prefix, domain, error):
    """Convenience method for handle_error"""
    handle_error(prefix, domain, error, syntax_error=True)


def generate_csv(domains, file_name):
    with open(file_name, 'w', encoding='utf-8', newline='\n') as output_file:
        writer = csv.DictWriter(output_file, fieldnames=domains[0].generate_results().keys())

        # First row should always be the headers
        writer.writeheader()

        for domain in domains:
            writer.writerow(domain.generate_results())
            output_file.flush()


def generate_json(domains):
    output = []
    for domain in domains:
        output.append(domain.generate_results())

    return json.dumps(output, indent=2, default=format_datetime)


# Taken from pshtt to keep formatting similar
def format_datetime(obj):
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, str):
        return obj
    else:
        return None


def remove_quotes(txt_record):
    """Remove double quotes and contatenate strings in a DNS TXT record

    A DNS TXT record can contain multiple double-quoted strings, and
    in that case the client has to remove the quotes and concatenate the
    strings.  This function does just that.

    Parameters
    ----------
    txt_record : str
        The DNS TXT record that possibly consists of multiple
        double-quoted strings.

    Returns
    -------
    str: The DNS TXT record with double-quoted strings unquoted and
    concatenated.
    """
    # This regular expression removes leading and trailing double quotes and
    # also removes any pairs of double quotes separated by one or more spaces.
    return re.sub('^"|"$|" +"', '', txt_record)
