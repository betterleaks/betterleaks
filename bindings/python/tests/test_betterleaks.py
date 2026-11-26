import os
import sys
import tempfile
from collections.abc import Mapping

import pytest

import betterleaks
from betterleaks import BetterleaksError, Finding

GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"
AWS_KEY = "AK" + "IALALEMEL33243OLIB"
AWS_SECRET = "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCY1234567890"


def test_reexports_sdk_on_posix():
    if sys.platform == "win32":
        pytest.skip("Windows uses CLI fallback instead of betterleaks-sdk")
    import betterleaks_sdk

    assert betterleaks.BetterleaksError is betterleaks_sdk.BetterleaksError
    assert betterleaks.Finding is betterleaks_sdk.Finding
    assert betterleaks.Location is betterleaks_sdk.Location
    assert betterleaks.Match is betterleaks_sdk.Match
    assert betterleaks.Scanner is betterleaks_sdk.Scanner
    assert betterleaks.create_scanner is betterleaks_sdk.create_scanner
    assert betterleaks.scan_file is betterleaks_sdk.scan_file
    assert betterleaks.scan_string is betterleaks_sdk.scan_string


def test_scan_string_and_mapping_contract():
    content = f"const token = '{GH_TOKEN}';"
    findings = betterleaks.scan_string(content)

    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding)
    assert isinstance(f, Mapping)
    assert f.rule_id == "github-pat"
    assert f.secret == GH_TOKEN
    assert f["rule_id"] == "github-pat"
    assert f["secret"] == GH_TOKEN
    assert dict(f) == f.to_dict()


def test_scan_string_multi_component_aws():
    content = f"""
    aws_access_key_id = {AWS_KEY}
    aws_secret_access_key = {AWS_SECRET}
    """
    findings = betterleaks.scan_string(content)
    f = next(item for item in findings if item.rule_id == "aws-access-token")
    assert f.secret == AWS_KEY
    assert len(f.component_sets) > 0


def test_scan_file_and_scanner():
    with tempfile.NamedTemporaryFile("w+", suffix=".py", delete=False) as fh:
        fh.write(f"API_KEY = '{GH_TOKEN}'\n")
        filename = fh.name

    try:
        findings = betterleaks.scan_file(filename)
        assert len(findings) == 1
        assert findings[0].rule_id == "github-pat"
        assert findings[0].file == filename
    finally:
        if os.path.exists(filename):
            os.remove(filename)

    inline = """
[[rules]]
id = "custom-inline"
description = "Inline rule"
regex = '''INLINE_[A-Z]{6}'''
keywords = ["INLINE_"]
"""
    with betterleaks.create_scanner(config_toml=inline) as scanner:
        res = scanner.scan_string("key = INLINE_ABCDEF")
        assert len(res) == 1
        assert res[0].rule_id == "custom-inline"

    with pytest.raises(BetterleaksError, match="closed"):
        scanner.scan_string("INLINE_ABCDEF")
