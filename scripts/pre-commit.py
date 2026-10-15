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
        # The hook owns the Git producer; the Betterleaks CLI/library only reads stdin.
        with subprocess.Popen(
            [
                "git", "diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-color",
                # Fixed prefixes keep file paths intact under diff.noprefix and similar settings.
                "--src-prefix=a/", "--dst-prefix=b/",
            ],
            stdout=subprocess.PIPE,
        ) as producer:
            try:
                result = subprocess.run(
                    ["betterleaks", "stdin", "--git-diff", "--redact"],
                    stdin=producer.stdout,
                )
            finally:
                producer.stdout.close()
            producer_status = producer.wait()
        if producer_status:
            sys.exit(producer_status if producer_status > 0 else 128 - producer_status)
    except OSError as err:
        print(f"Could not run betterleaks: {err}", file=sys.stderr)
        sys.exit(1)
    sys.exit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
else:
    print('betterleaks precommit disabled\
     (enable with `git config hooks.betterleaks true`)')
