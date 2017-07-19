"""TrustyMail A tool for scanning DNS mail records for evaluating security.
Usage:
  trustymail (INPUT ...) [options]
  trustymail (INPUT ...) [--output=OUTFILE] [--timeout=TIMEOUT] [--mx] [--spf] [--dmarc] [--debug] [--json]
  trustymail (-h | --help)
Options:
  -h --help                   Show this message.
  -o --output=OUTFILE         Name of output file. (Default results)
  -t --timeout=TIMEOUT        Override timeout of DNS lookup in seconds. (Default 5)
  --mx                        Only check mx records
  --spf                       Only check spf records
  --dmarc                     Only check dmarc records
  --json                      Output is in json format (default csv)
  --debug                     Output should include error messages.

Notes:
  If the first INPUT ends with .csv domains will be read from the csv at
  the given location.

  Output is default written to stdout unless an output is provided. When
  using the agency flag the public 18F csv will be used to determine
  which domains to scan.

  If no scan types are specified then all are ran against given domains.
"""

import logging
import docopt
import os
import errno

from trustymail import trustymail

base_domains = {}


def main():
    args = docopt.docopt(__doc__, version='v0.0.1')

    if args["--debug"]:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    # Allow for user to input a csv for many domain names.
    if args["INPUT"][0].endswith(".csv"):
        domains = trustymail.domain_list_from_csv(open(args["INPUT"][0]))
    else:
        domains = args["INPUT"]

    if args["--timeout"] is not None:
        timeout = int(args["--timeout"])
    else:
        timeout = 5

    # User might not want every scan performed.
    scan_types = {
                    "mx": args["--mx"],
                    "spf": args["--spf"],
                    "dmarc": args["--dmarc"]
                 }

    domain_scans = []
    for domain_name in domains:
        domain_scans.append(trustymail.scan(domain_name, timeout, scan_types))

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
        json_out = trustymail.generate_json(domain_scans)
        if args["--output"] is None:
            print(json_out)
        else:
            write(json_out, output_file_name)
            logging.warn("Wrote results to %s." % output_file_name)
    else:
        trustymail.generate_csv(domain_scans, output_file_name)


def write(content, out_file):
    parent = os.path.dirname(out_file)
    if parent is not "":
        mkdir_p(parent)

    f = open(out_file, 'w')  # no utf-8 in python 2
    f.write(content)
    f.close()


# mkdir -p in python, from:
# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise

if __name__ == '__main__':
    main()
