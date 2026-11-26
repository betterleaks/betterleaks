from collections.abc import Mapping

import pytest

import betterleaks_sdk
from betterleaks_sdk import BetterleaksError, Finding

# Construct tokens dynamically so repository static push protection is not triggered.
GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"
SLACK_TOKEN = "xo" + "xb-123456789012-1234567890123-123456789012345678901234"
AWS_KEY = "AK" + "IALALEMEL33243OLIB"
AWS_SECRET = "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCY1234567890"


def test_scan_string_github_pat():
    content = f"const token = '{GH_TOKEN}';"
    findings = betterleaks_sdk.scan_string(content)

    assert len(findings) >= 1
    f = findings[0]
    assert isinstance(f, Finding)
    assert f.rule_id == "github-pat"
    assert f.secret == GH_TOKEN
    assert f.confidence in ("low", "medium", "high")
    assert f.location.start_line == 1
    assert f.location.start_column > 0


def test_scan_string_clean():
    content = "This is completely normal text with no credentials or secrets."
    findings = betterleaks_sdk.scan_string(content)
    assert findings == []


def test_scan_string_empty():
    findings = betterleaks_sdk.scan_string("")
    assert findings == []


def test_scan_string_dict_access():
    content = f"token = '{GH_TOKEN}'"
    findings = betterleaks_sdk.scan_string(content)

    assert len(findings) == 1
    f = findings[0]

    assert isinstance(f, Mapping)
    assert f["rule_id"] == "github-pat"
    assert f["secret"] == GH_TOKEN
    assert f.get("rule_id") == "github-pat"
    assert f.get("non_existent", "default") == "default"
    assert "rule_id" in f
    assert "secret" in f
    assert "non_existent" not in f
    assert len(f) > 0
    assert "rule_id" in list(f)

    with pytest.raises(KeyError):
        _ = f["from_dict"]
    with pytest.raises(KeyError):
        _ = f["to_dict"]

    constructed_dict = dict(f)
    assert isinstance(constructed_dict, dict)
    assert constructed_dict["rule_id"] == "github-pat"
    assert constructed_dict["secret"] == GH_TOKEN
    assert "file" in constructed_dict
    assert set(constructed_dict.keys()) == set(f.keys())

    d = f.to_dict()
    assert isinstance(d, dict)
    assert d["rule_id"] == "github-pat"
    assert d["secret"] == GH_TOKEN
    assert d == constructed_dict


def test_scan_string_multiline_positions():
    content = f"line1\nline2\n{GH_TOKEN}\nline4"
    findings = betterleaks_sdk.scan_string(content)

    assert len(findings) == 1
    f = findings[0]
    assert f.location.start_line == 3
    assert f.location.end_line == 3


def test_scan_string_invalid_config():
    with pytest.raises(BetterleaksError):
        betterleaks_sdk.scan_string(
            "test", config_path="/non/existent/path/betterleaks.toml"
        )


def test_scan_string_slack_token():
    content = f"token = '{SLACK_TOKEN}'"
    findings = betterleaks_sdk.scan_string(content)
    assert len(findings) >= 1
    assert any(f.rule_id == "slack-bot-token" for f in findings)


def test_scan_string_multi_component_aws():
    content = f"""
    aws_access_key_id = {AWS_KEY}
    aws_secret_access_key = {AWS_SECRET}
    """
    findings = betterleaks_sdk.scan_string(content)
    assert len(findings) >= 1
    f = next(f for f in findings if f.rule_id == "aws-access-token")
    assert f.secret == AWS_KEY
    assert len(f.component_sets) > 0
    exported = dict(f)
    assert exported["component_sets"] == f.component_sets
    assert f.to_dict()["component_sets"] == f.component_sets
