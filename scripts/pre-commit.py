#!/usr/bin/env python3
"""Helper script to be used as a pre-commit hook."""
import sys
import subprocess


def betterleaksEnabled():
    """Determine if the pre-commit hook for betterleaks is enabled."""
    out = subprocess.getoutput("git config --bool hooks.betterleaks")
    if out == "false":
        return False
    return True


if betterleaksEnabled():
    try:
        result = subprocess.run(["betterleaks", "git", "--staged", "--offline", "--redact"])
    except OSError as err:
        print(f"Could not run betterleaks: {err}", file=sys.stderr)
        sys.exit(1)
    sys.exit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
else:
    print('betterleaks precommit disabled\
     (enable with `git config hooks.betterleaks true`)')
