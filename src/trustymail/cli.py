"""trustymail: A tool for scanning DNS mail records for evaluating security.

Usage:
  trustymail (INPUT ...) [options]
  trustymail (INPUT ...) [--output=OUTFILE] [--timeout=TIMEOUT] [--smtp-timeout=TIMEOUT] [--smtp-localhost=HOSTNAME] [--smtp-ports=PORTS] [--no-smtp-cache] [--mx] [--starttls] [--spf] [--dmarc] [--debug] [--json] [--dns=HOSTNAMES] [--psl-filename=FILENAME] [--psl-read-only]
  trustymail (-h | --help)

Options:
  -h --help                   Show this message.
  -o --output=OUTFILE         Name of output file.  (Default results)
  -t --timeout=TIMEOUT        The DNS lookup timeout in seconds.  (Default is 5.)
  --smtp-timeout=TIMEOUT      The SMTP connection timeout in seconds.  (Default is 5.)
  --smtp-localhost=HOSTNAME   The hostname to use when connecting to SMTP
                              servers.  (Default is the FQDN of the host from
                              which trustymail is being run.)
  --smtp-ports=PORTS          A comma-delimited list of ports at which to look
                              for SMTP servers.  (Default is '25,465,587'.)
  --no-smtp-cache             Do not cache SMTP results during the run.  This
                              may results in slower scans due to testing the
                              same mail servers multiple times.
  --mx                        Only check MX records.
  --starttls                  Only check MX records and STARTTLS support.
                              (Implies --mx.)
  --spf                       Only check SPF records.
  --dmarc                     Only check DMARC records.
  --json                      Output is in JSON format.  (Default is CSV.)
  --debug                     Output should include more verbose logging.
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

Notes:
   If no scan type options are specified, all are run against a given domain/input.
"""
# Standard Python Libraries
# Built-in imports
import errno
import logging
import os

# Third-Party Libraries
# Dependency imports
import docopt

# Local imports
from . import trustymail
from ._version import __version__

# The default ports to be checked to see if an SMTP server is listening.
_DEFAULT_SMTP_PORTS = {25, 465, 587}


def main():
    """Perform a trustymail scan using the provided options."""
    args = docopt.docopt(__doc__, version=__version__)

    # Monkey patching trustymail to make it cache the PSL where we want
    if args["--psl-filename"] is not None:
        trustymail.PublicSuffixListFilename = args["--psl-filename"]
    # Monkey patching trustymail to make the PSL cache read-only
    if args["--psl-read-only"]:
        trustymail.PublicSuffixListReadOnly = True
    # cisagov Libraries
    import trustymail.trustymail as tmail

    log_level = logging.WARN
    if args["--debug"]:
        log_level = logging.DEBUG
    logging.basicConfig(format="%(asctime)-15s %(message)s", level=log_level)

    # Allow for user to input a csv for many domain names.
    if args["INPUT"][0].endswith(".csv"):
        domains = tmail.domain_list_from_csv(open(args["INPUT"][0]))
    else:
        domains = args["INPUT"]

    if args["--timeout"] is not None:
        timeout = int(args["--timeout"])
    else:
        timeout = 5

    if args["--smtp-timeout"] is not None:
        smtp_timeout = int(args["--smtp-timeout"])
    else:
        smtp_timeout = 5

    if args["--smtp-localhost"] is not None:
        smtp_localhost = args["--smtp-localhost"]
    else:
        smtp_localhost = None

    if args["--smtp-ports"] is not None:
        smtp_ports = {int(port) for port in args["--smtp-ports"].split(",")}
    else:
        smtp_ports = _DEFAULT_SMTP_PORTS

    if args["--dns"] is not None:
        dns_hostnames = args["--dns"].split(",")
    else:
        dns_hostnames = None

    # --starttls implies --mx
    if args["--starttls"]:
        args["--mx"] = True

    # User might not want every scan performed.
    scan_types = {
        "mx": args["--mx"],
        "starttls": args["--starttls"],
        "spf": args["--spf"],
        "dmarc": args["--dmarc"],
    }

    domain_scans = []
    for domain_name in domains:
        domain_scans.append(
            tmail.scan(
                domain_name,
                timeout,
                smtp_timeout,
                smtp_localhost,
                smtp_ports,
                not args["--no-smtp-cache"],
                scan_types,
                dns_hostnames,
            )
        )

    # Default output file name is results.
    if args["--output"] is None:
        output_file_name = "results"
    else:
        output_file_name = args["--output"]

    # Ensure file extension is present in filename.
    if args["--json"] and ".json" not in output_file_name:
        output_file_name += ".json"
    elif ".csv" not in output_file_name:
        output_file_name += ".csv"

    if args["--json"]:
        json_out = tmail.generate_json(domain_scans)
        if args["--output"] is None:
            print(json_out)
        else:
            write(json_out, output_file_name)
            logging.warn("Wrote results to %s." % output_file_name)
    else:
        tmail.generate_csv(domain_scans, output_file_name)


def write(content, out_file):
    """Write the provided content to a file after ensuring all intermediate directories exist."""
    parent = os.path.dirname(out_file)
    if parent != "":
        mkdir_p(parent)

    f = open(out_file, "w")  # no utf-8 in python 2
    f.write(content)
    f.close()


# mkdir -p in python, from:
# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    """Make a directory and all intermediate directories in its path."""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise
