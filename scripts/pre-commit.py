#!/usr/bin/env python3
"""Helper script to be used as a pre-commit hook."""
import os
import sys
import subprocess


def betterleaksEnabled():
    """Determine if the pre-commit hook for betterleaks is enabled.
    
    Checks both 'hooks.betterleaks' and 'hooks.gitleaks' for backwards compatibility.
    """
    # Check betterleaks config first (preferred)
    out = subprocess.getoutput("git config --bool hooks.betterleaks")
    if out == "true":
        return True
    if out == "false":
        return False
    # Fall back to gitleaks config for backwards compatibility
    out = subprocess.getoutput("git config --bool hooks.gitleaks")
    if out == "false":
        return False
    return True


if betterleaksEnabled():
    exitCode = os.WEXITSTATUS(os.system('betterleaks git --pre-commit --staged -v'))
    if exitCode == 1:
        print('''Warning: betterleaks has detected sensitive information in your changes.
To disable the betterleaks precommit hook run the following command:

    git config hooks.betterleaks false
''')
        sys.exit(1)
else:
    print('betterleaks precommit disabled\
     (enable with `git config hooks.betterleaks true`)')
