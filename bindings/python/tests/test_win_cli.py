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
            reusable = _win_cli.create_scanner(config_path="rules.toml")
            res_a = _win_cli.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_a] == ["dir-a"]
            assert os.path.abspath("rules.toml") in _win_cli._scanner_cache

            os.chdir(dir_b)
            # Reusable scanner keeps using dir_a/rules.toml even after chdir(dir_b).
            res_reusable = reusable.scan_string("DIRA_1234 DIRB_1234")
            assert [f.rule_id for f in res_reusable] == ["dir-a"]
            reusable.close()

            res_b = _win_cli.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_b] == ["dir-b"]
            assert _win_cli.get_cached_backing(
                "rules.toml"
            ) is not _win_cli.get_cached_backing(os.path.join(dir_a, "rules.toml"))
        finally:
            os.chdir(orig_cwd)


def test_win_cli_special_filenames_and_magic_bytes_text():
    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            os.chdir(tmpdir)
            for fname in ("stdin", "version", "-leading-dash.txt"):
                with open(fname, "w", encoding="utf-8") as fh:
                    fh.write(f"TOKEN={GH_TOKEN}\n")
                findings = _win_cli.scan_file(fname)
                assert len(findings) == 1
                assert findings[0].rule_id == "github-pat"

            magic_txt = os.path.join(tmpdir, "payload.txt")
            with open(magic_txt, "wb") as fh:
                fh.write(b"PK\x03\x04\n" + f"TOKEN={GH_TOKEN}\n".encode())
            magic_findings = _win_cli.scan_file(magic_txt)
            assert len(magic_findings) == 1
            assert magic_findings[0].rule_id == "github-pat"
        finally:
            os.chdir(orig_cwd)


def test_win_cli_concurrent_cache_eviction():
    import concurrent.futures

    with tempfile.TemporaryDirectory() as tmpdir:
        configs = []
        for idx in range(20):
            cfg_path = os.path.join(tmpdir, f"rule_{idx}.toml")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                fh.write(
                    f"[[rules]]\nid = 'win-{idx}'\n"
                    f"regex = '''WCONC_{idx:02d}_[0-9]{{4}}'''\n"
                    f"keywords = ['WCONC_{idx:02d}_']\n"
                )
            configs.append((idx, cfg_path))

        def _worker(item):
            idx, cfg_path = item
            findings = _win_cli.scan_string(
                f"secret = WCONC_{idx:02d}_1234", config_path=cfg_path
            )
            return [f.rule_id for f in findings]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_worker, configs * 2))

        assert len(results) == len(configs) * 2
        for expected_idx, actual in zip([i for i, _ in configs] * 2, results):
            assert actual == [f"win-{expected_idx}"]
