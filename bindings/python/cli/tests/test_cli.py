import json
import os
import subprocess

from betterleaks_cli import get_binary_path

GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"


def test_cli_binary_exists_and_runs_version():
    binary = get_binary_path()
    assert os.path.isfile(binary)
    proc = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() != ""


def test_cli_stdin_scan():
    binary = get_binary_path()
    proc = subprocess.run(
        [
            binary,
            "stdin",
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
        ],
        input=f"TOKEN={GH_TOKEN}\n",
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    findings = payload.get("findings", [])
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "github-pat"
