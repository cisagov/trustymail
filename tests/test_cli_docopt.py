"""Regression checks for parsing the trustymail command-line help text."""

# Third-Party Libraries
import docopt
import pytest

# cisagov Libraries
from trustymail import cli


def test_cli_options_parse_without_duplicate_dns_definition():
    """Treat the DNS example as help text rather than another CLI option."""
    assert cli.__doc__ is not None
    args = docopt.docopt(cli.__doc__, argv=["example.org", "--dns=8.8.8.8,8.8.4.4"])
    assert args["INPUT"] == ["example.org"]
    assert args["--dns"] == "8.8.8.8,8.8.4.4"


def test_cli_help_renders_without_option_collisions(capsys):
    """Show help without raising a docopt language error."""
    assert cli.__doc__ is not None
    with pytest.raises(SystemExit) as exc_info:
        docopt.docopt(cli.__doc__, argv=["--help"])
    assert exc_info.value.code in (None, 0)
    assert "  --dns=HOSTNAMES" in capsys.readouterr().out
