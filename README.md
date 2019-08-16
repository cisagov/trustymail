# Trustworthy Mail #

[![Latest Version](https://img.shields.io/pypi/v/trustymail.svg)](https://pypi.org/project/trustymail/)
[![Build Status](https://travis-ci.com/cisagov/trustymail.svg?branch=develop)](https://travis-ci.com/cisagov/trustymail)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/trustymail/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/trustymail?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/trustymail.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/trustymail/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/trustymail.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/trustymail/context:python)

`trustymail` is a tool that evaluates SPF/DMARC records set in a
domain's DNS. It also checks the mail servers listed in a domain's MX
records for STARTTLS support. It saves its results to CSV or JSON.

## Getting Started ##

`trustymail` requires **Python 3.6+**. Python 2 is not supported.

`trustymail` can be installed as a module or run directly from the
repository.

### Installed as a module ###

`trustymail` can be installed directly via pip:

```console
pip install trustymail
```

It can then be run directly:

```console
trustymail [options] example.com
```

### Running directly ###

To run the tool locally from the repository, without installing, first
install the requirements:

```console
pip install -r requirements.txt
```

Then run the CLI:

```console
python scripts/trustymail [options] example.com
```

### Using Docker (optional)

```console
./run [opts]
```

`opts` are the same arguments that would get passed to `trustymail`.

### Usage and examples ###

```console
trustymail [options] INPUT

trustymail dhs.gov
trustymail --output=homeland.csv --debug cisa.gov dhs.gov us-cert.gov usss.gov
trustymail agencies.csv
```

Note: if INPUT ends with `.csv`, domains will be read from CSV. CSV
output will always be written to disk, defaulting to `results.csv`.

#### Options ####

```console
  -h --help                   Show this message.
  -o --output=OUTFILE         Name of output file. (Default results)
  -t --timeout=TIMEOUT        The DNS lookup timeout in seconds. (Default is 5.)
  --smtp-timeout=TIMEOUT      The SMTP connection timeout in seconds. (Default
                              is 5.)
  --smtp-localhost=HOSTNAME   The hostname to use when connecting to SMTP
                              servers.  (Default is the FQDN of the host from
                              which trustymail is being run.)
  --smtp-ports=PORTS          A comma-delimited list of ports at which to look
                              for SMTP servers.  (Default is '25,465,587'.)
  --no-smtp-cache             Do not cache SMTP results during the run.  This
                              may results in slower scans due to testing the
                              same mail servers multiple times.
  --mx                        Only check mx records
  --starttls                  Only check mx records and STARTTLS support.
                              (Implies --mx.)
  --spf                       Only check spf records
  --dmarc                     Only check dmarc records
  --debug                     Output should include error messages.
  --dns=HOSTNAMES             A comma-delimited list of DNS servers to query
                              against.  For example, if you want to use
                              Google's DNS then you would use the
                              value --dns-hostnames='8.8.8.8,8.8.4.4'.  By
                              default the DNS configuration of the host OS
                              (/etc/resolv.conf) is used.  Note that
                              the host's DNS configuration is not used at all
                              if this option is used.
  --psl-filename=FILENAME     The name of the file where the public suffix list
                              (PSL) cache will be saved.  If set to the name of
                              an existing file then that file will be used as
                              the PSL.  If not present then the PSL cache will
                              be saved to a file in the current directory called
                              public_suffix_list.dat.
  --psl-read-only             If present, then the public suffix list (PSL)
                              cache will be read but never overwritten.  This
                              is useful when running in AWS Lambda, for
                              instance, where the local filesystem is read-only.
```

## What's Checked? ##

For a given domain, MX records, SPF records (TXT), DMARC (TXT, at
\_dmarc.<domain>), and support for STARTTLS are checked. Resource records can also be checked for DNSSEC if the resolver used is DNSSEC-aware.

The following values are returned in `results.csv`:

### Domain and redirect info ###

* `Domain` - The domain you're scanning!
* `Base Domain` - The base domain of `Domain`. For example, for a
  Domain of `sub.example.gov`, the Base Domain will be
  `example.gov`. Usually this is the second-level domain, but
  `trustymail` will download and factor in the [Public Suffix
  List](https://publicsuffix.org) when calculating the base domain.
* `Live` - The domain is actually published in the DNS.

### Mail sending ###

* `MX Record` - If an MX record was found that contains at least a
  single mail server.
* `MX Record DNSSEC` - A boolean value indicating whether or not the
  DNS record is protected by DNSSEC.
* `Mail Servers` - The list of hosts found in the MX record.
* `Mail Server Ports Tested` - A list of the ports tested for SMTP and
  STARTTLS support.
* `Domain Supports SMTP` - True if and only if __any__ mail servers
  specified in a MX record associated with the domain supports SMTP.
* `Domain Supports SMTP Results` - A list of the mail server and port
  combinations that support SMTP.
* `Domain Supports STARTTLS` - True if and only if __all__ mail
  servers that support SMTP also support STARTTLS.
* `Domain Supports STARTTLS Results` - A list of the mail server and
  port combinations that support STARTTLS.

### SPF ###

* `SPF Record` - Whether or not a SPF record was found.
* `SPF Record DNSSEC` - A boolean value indicating whether or not the
  DNS record is protected by DNSSEC.
* `Valid SPF` - Whether the SPF record found is syntactically correct,
  per RFC 4408.
* `SPF Results` - The textual representation of any SPF record found
  for the domain.

### DMARC ###

* `DMARC Record` - True/False whether or not a DMARC record was found.
* `DMARC Record DNSSEC` - A boolean value indicating whether or not
  the DNS record is protected by DNSSEC.
* `Valid DMARC` - Whether the DMARC record found is syntactically
  correct.
* `DMARC Results` - The DMARC record that was discovered when querying
  DNS.
* `DMARC Record on Base Domain`, `DMARC Record on Base Domain DNSSEC`,
  `Valid DMARC Record on Base Domain`, `DMARC Results on Base
  Domain` - Same definition as above, but returns the result for the
  Base Domain. This is important in DMARC because if there isn't a
  DMARC record at the domain, the base domain (or "Organizational
  Domain", per [RFC
  7489](https://tools.ietf.org/html/rfc7489#section-6.6.3)), is
  checked and applied.
* `DMARC Policy` - An adjudication, based on any policies found in
  `DMARC Results` and `DMARC Results on Base Domain`, of the relevant
  DMARC policy that applies.
* `DMARC Subdomain Policy` - An adjudication, based on any policies
  found in `DMARC Results` and `DMARC Results on Base Domain`, of the
  relevant DMARC subdomain policy that applies.
* `DMARC Policy Percentage` - The percentage of mail that should be
  subjected to the `DMARC Policy` according to the `DMARC Results`.
* `DMARC Aggregate Report URIs` - A list of the DMARC aggregate report
  URIs specified by the domain.
* `DMARC Forensic Report URIs` - A list of the DMARC forensic report
  URIs specified by the domain.
* `DMARC Has Aggregate Report URI` - A boolean value that indicates if
  `DMARC Results` included `rua` URIs that tell recipients where to
  send DMARC aggregate reports.
* `DMARC Has Forensic Report URI` - A boolean value that indicates if
  `DMARC Results` included `ruf` URIs that tell recipients where to
  send DMARC forensic reports.
* `DMARC Reporting Address Acceptance Error` - A boolean value that is
  True if one or more of the domains listed in the aggregate and
  forensic report URIs does not indicate that it accepts DMARC reports
  from the domain being tested.

### Etc. ###

* `Syntax Errors` - A list of syntax errors that were encountered when
  analyzing SPF records.
* `Debug Info` - A list of any other warnings or errors encountered,
  such as DNS failures.  These can be helpful when determining how
  `trustymail` reached its conclusions, and are indispensible for bug
  reports.

## Public domain ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
