"""Tests for command-line configuration."""

# Standard Python Libraries
from collections import defaultdict
import os
from unittest.mock import Mock

# Third-Party Libraries
import pytest

# cisagov Libraries
from trustymail import cli, domain, trustymail


@pytest.mark.parametrize("filename", [None, "custom.dat"])
@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("cache_state", ["missing", "fresh", "stale"])
def test_psl_options(monkeypatch, tmp_path, filename, read_only, cache_state):
    """Honor the selected cache filename and update policy when scanning."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(domain, "PublicSuffixListFilename", "public_suffix_list.dat")
    monkeypatch.setattr(domain, "PublicSuffixListReadOnly", False)
    cache = tmp_path / (filename or "public_suffix_list.dat")
    if cache_state != "missing":
        cache.write_text("com\n", encoding="utf-8")
        if cache_state == "stale":
            os.utime(cache, (0, 0))
        original_mtime = cache.stat().st_mtime_ns

    # Isolate configuration from argument parsing and DNS/SMTP scanning.
    args = defaultdict(
        lambda: None,
        {
            "INPUT": ["example.com"],
            "--psl-filename": filename,
            "--psl-read-only": read_only,
        },
    )
    monkeypatch.setattr(cli.docopt, "docopt", lambda *a, **kw: args)
    suffixes = []

    def scan(*args):
        suffixes.append(domain.get_public_suffix("example.com"))

    monkeypatch.setattr(trustymail, "scan", scan)
    monkeypatch.setattr(trustymail, "generate_csv", Mock())

    def update(filename):
        with open(filename, "w", encoding="utf-8") as cache_file:
            cache_file.write("com\n")

    download = Mock(side_effect=update)
    monkeypatch.setattr(domain, "updatePSL", download)

    if read_only and cache_state == "missing":
        with pytest.raises(FileNotFoundError):
            cli.main()
    else:
        cli.main()
        assert suffixes == ["example.com"]

    if not read_only and cache_state != "fresh":
        download.assert_called_once_with(str(cache.name))
    else:
        download.assert_not_called()
        if cache_state != "missing":
            assert cache.stat().st_mtime_ns == original_mtime
            assert cache.read_text(encoding="utf-8") == "com\n"
    if filename:
        assert not (tmp_path / "public_suffix_list.dat").exists()
