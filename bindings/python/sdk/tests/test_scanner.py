import os
import sys
import tempfile
import zipfile

import pytest

import betterleaks_sdk
from betterleaks_sdk import BetterleaksError
from betterleaks_sdk._lib import (
    _get_native_library,
    _scanner_cache,
    get_cached_backing,
)

GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"


def test_scanner_inline_config_and_lifecycle():
    config_toml = """
[[rules]]
id = "custom-inline"
description = "Inline rule"
regex = '''INLINE_[A-Z]{6}'''
keywords = ["INLINE_"]
"""
    with betterleaks_sdk.create_scanner(config_toml=config_toml) as scanner:
        findings = scanner.scan_string("key = INLINE_ABCDEF")
        assert len(findings) == 1
        assert findings[0].rule_id == "custom-inline"
        assert findings[0].secret == "INLINE_ABCDEF"

        findings_with_nul = scanner.scan_string("é\x00key = INLINE_ABCDEF")
        assert len(findings_with_nul) == 1
        assert findings_with_nul[0].rule_id == "custom-inline"

    scanner.close()
    with pytest.raises(BetterleaksError, match="closed"):
        scanner.scan_string("INLINE_ABCDEF")


def test_scanner_custom_config_file():
    config_toml = """
[[rules]]
id = "custom-file-rule"
description = "File config rule"
regex = '''FILERULE_[0-9]{6}'''
keywords = ["FILERULE_"]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as cfg:
        cfg.write(config_toml)
        cfg_path = cfg.name

    try:
        with betterleaks_sdk.create_scanner(config_path=cfg_path) as scanner:
            findings = scanner.scan_string("val = FILERULE_123456")
            assert len(findings) == 1
            assert findings[0].rule_id == "custom-file-rule"
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_relative_config_cache_key_resolves_abspath():
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
            res_a = betterleaks_sdk.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_a] == ["dir-a"]
            assert os.path.abspath("rules.toml") in _scanner_cache

            os.chdir(dir_b)
            res_b = betterleaks_sdk.scan_string(
                "DIRA_1234 DIRB_1234", config_path="rules.toml"
            )
            assert [f.rule_id for f in res_b] == ["dir-b"]
            assert get_cached_backing("rules.toml") is not get_cached_backing(
                os.path.join(dir_a, "rules.toml")
            )
        finally:
            os.chdir(orig_cwd)


def test_scanner_limits_and_archive_rejection():
    with betterleaks_sdk.create_scanner(
        max_input_bytes=16, max_findings=1
    ) as limited, pytest.raises(BetterleaksError, match="size limit|max_input_bytes"):
        limited.scan_string("x" * 32)

    with betterleaks_sdk.create_scanner(
        max_findings=1
    ) as limited_findings, pytest.raises(BetterleaksError, match="max_findings"):
        limited_findings.scan_string(f"a={GH_TOKEN}\nb={GH_TOKEN}\n")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zpath = zf.name
    try:
        with zipfile.ZipFile(zpath, "w") as archive:
            archive.writestr("secret.txt", f"TOKEN={GH_TOKEN}\n")
        with betterleaks_sdk.create_scanner() as scanner, pytest.raises(
            BetterleaksError, match="archive"
        ):
            scanner.scan_file(zpath)
    finally:
        if os.path.exists(zpath):
            os.remove(zpath)


def test_windows_unsupported(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(BetterleaksError, match="Windows is not supported"):
        _get_native_library()
