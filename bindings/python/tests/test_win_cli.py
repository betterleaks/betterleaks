import os
import tempfile
import zipfile

import pytest

from betterleaks import _win_cli
from betterleaks._models import BetterleaksError, Finding

GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"


def test_win_cli_scan_string_and_file(monkeypatch):
    monkeypatch.setenv("BETTERLEAKS_VALIDATE", "true")
    monkeypatch.setenv("BETTERLEAKS_ANALYZE", "true")
    monkeypatch.setenv("BETTERLEAKS_CONFIG", "/nonexistent/override.toml")

    with _win_cli.create_scanner() as scanner:
        findings = scanner.scan_string(f"token = '{GH_TOKEN}'")
        assert len(findings) == 1
        assert isinstance(findings[0], Finding)
        assert findings[0].rule_id == "github-pat"
        assert findings[0].secret == GH_TOKEN

        assert scanner.scan_string("ordinary clean text") == []

        with tempfile.NamedTemporaryFile("w+", suffix=".env", delete=False) as fh:
            fh.write(f"GITHUB_TOKEN={GH_TOKEN}\n")
            path = fh.name
        try:
            file_findings = scanner.scan_file(path)
            assert len(file_findings) == 1
            assert file_findings[0].rule_id == "github-pat"
            assert file_findings[0].location.path == path
        finally:
            if os.path.exists(path):
                os.remove(path)

    with pytest.raises(BetterleaksError, match="closed"):
        scanner.scan_string("clean")


def test_win_cli_inline_config_limits_and_archive(monkeypatch):
    monkeypatch.setenv("BETTERLEAKS_CONFIG", "/nonexistent/override.toml")
    inline = (
        "[[rules]]\n"
        "id = 'win-inline'\n"
        "regex = '''WININLINE_[A-Z]{4}'''\n"
        "keywords = ['WININLINE_']\n"
    )
    with _win_cli.create_scanner(config_toml=inline) as inline_scanner:
        res = inline_scanner.scan_string("val = WININLINE_TEST")
        assert [item.rule_id for item in res] == ["win-inline"]

    with _win_cli.create_scanner(max_input_bytes=16, max_findings=1) as limited:
        with pytest.raises(BetterleaksError, match="max_input_bytes"):
            limited.scan_string("x" * 32)
        with pytest.raises(BetterleaksError, match="max_findings"):
            limited._backing._parse_cli_output(
                type("P", (), {"returncode": 0, "stdout": b"[{}, {}]", "stderr": b""})()
            )

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zpath = zf.name
    try:
        with zipfile.ZipFile(zpath, "w") as archive:
            archive.writestr("secret.txt", f"TOKEN={GH_TOKEN}\n")
        with _win_cli.create_scanner() as archive_scanner, pytest.raises(
            BetterleaksError, match="archive"
        ):
            archive_scanner.scan_file(zpath)
    finally:
        if os.path.exists(zpath):
            os.remove(zpath)


def test_win_cli_relative_config_cache_key_resolves_abspath():
    cfg_a = (
        "[[rules]]\nid = 'dir-a'\nregex = '''DIRA_[0-9]{4}'''\nkeywords = ['DIRA_']\n"
    )
    cfg_b = (
        "[[rules]]\nid = 'dir-b'\nregex = '''DIRB_[0-9]{4}'''\nkeywords = ['DIRB_']\n"
    )

    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as dir_a, tempfile.TemporaryDirectory() as dir_b:
        try:
            with open(os.path.join(dir_a, "rules.toml"), "w", encoding="utf-8") as fh:
                fh.write(cfg_a)
            with open(os.path.join(dir_b, "rules.toml"), "w", encoding="utf-8") as fh:
                fh.write(cfg_b)

            os.chdir(dir_a)
            res_a = _win_cli.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_a] == ["dir-a"]
            assert os.path.abspath("rules.toml") in _win_cli._scanner_cache

            os.chdir(dir_b)
            res_b = _win_cli.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_b] == ["dir-b"]
            assert _win_cli.get_cached_backing(
                "rules.toml"
            ) is not _win_cli.get_cached_backing(os.path.join(dir_a, "rules.toml"))
        finally:
            os.chdir(orig_cwd)
