## Trustworthy Mail  :lock:
`TrustyMail` is a tool that evaluates SPF/DMARC DNS record configurations to recommend best practices for the records. It saves its results to a CSV.

#### Usage and examples

```bash
python cli [options] INPUT

python cli dhs.gov
python cli --output=homeland.csv --debug dhs.gov us-cert.gov usss.gov
python cli agencies.csv
```
Note: if INPUT ends with `.csv`, domains will be read from CSV. CSV output will always be written to disk, defaulting to `results.csv`.

#### Options
```bash
  -h --help                   Show this message.
  -o --output=OUTFILE         Name of output file. (Default results)
  -t --timeout=TIMEOUT        Override timeout of DNS lookup in seconds. (Default 5)
  --mx                        Only check mx records
  --spf                       Only check spf records
  --dmarc                     Only check dmarc records
  --debug                     Output should include error messages.
```

## What's Checked?
The following DNS records are checked:
* `DMARC`
* `SPF`
* `MX`

The following values are returned in `results.csv`:
#### DNS record info
* `Sends Mail` - If an MX record was found that contains at least a single mail server.
* `SPF Record` - True/False whether or not a SPF record was found.
* `SPF Results` -  The textual representation of any SPF records found for the domain.
* `Domain` - The domain is "live" if any endpoint is live.
* `DMARC Record` - The domain is a "redirect domain" if at least one endpoint is a redirect, and all endpoints are either redirects or down.
* `DMARC Results` - If a domain is a "redirect domain", where does it redirect to?
* `Mail Servers` - A list of all of the mail servers found in the MX record.
* `Valid SPF` - True/False if the SPF is properly configured according to RFC 4408
* `Valid DMARC` - True/False if the DMARC is properly configured.
* `Syntax Errors` - A list of all syntax errors that were detected when scanning either DMARC or SPF records.
