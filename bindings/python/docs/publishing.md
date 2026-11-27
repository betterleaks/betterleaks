# Publishing the Python packages

Betterleaks publishes three projects from one v2 release tag. The CLI wheel owns the executable. The SDK wheel owns the Python bindings and native library. The umbrella wheel depends on that release’s exact CLI and SDK versions. On Windows the umbrella installs the CLI.

## Registry setup

In the Betterleaks organization on PyPI, create or select the projects `betterleaks-cli`, `betterleaks-sdk`, and `betterleaks`. On each project, open **Manage → Publishing** and register GitHub Actions with the following values.

| Field | PyPI trusted publisher |
| --- | --- |
| Repository owner | `betterleaks` |
| Repository name | `betterleaks` |
| Workflow filename | `python-release.yml` |
| Environment | `pypi` |

For a new PyPI project, register an account-level pending publisher with the same values. PyPI authenticates the workflow via OIDC without a registry token.

Under repository **Settings → Environments → pypi**, allow deployments only from the `main` branch and add a required reviewer. Protect changes to workflows, packaging code, and release tags through repository rules. The publishing workflow runs on `main` and verifies the release tag separately.

[PyPI organization projects](https://docs.pypi.org/organization-accounts/actions/project-actions/) · [Trusted publishers](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)

## Cutting an RC or stable release

1. Merge the packaging changes and confirm **Python distributions** passes on the intended commit. Push the normal Betterleaks release tag. For example, `v2.0.0-rc.N` maps to Python version `2.0.0rcN` (replace N with the release number).
2. Once **Release** succeeds, **Publish Python distributions** validates the upstream repository, run, tag, commit and ancestry on main. It verifies the signed CLI checksums and signer identity from that Release run, packages the same GoReleaser executables used by npm, and builds the SDK from the tagged commit. CI tests the native wheels on each supported platform, installs the umbrella from the wheelhouse, and checks the complete set of files.
3. The smoke job installs the exact version from the validated wheels in a fresh environment. It checks dependencies, runs the CLI, and scans with a custom SDK rule. Review the version and smoke result, then approve the `pypi` deployment in GitHub Actions. The workflow publishes the CLI, SDK and umbrella to PyPI in that order from the same artifact, with attestations.
4. In a fresh virtual environment, install the exact version, run `betterleaks --version`, and on a native SDK platform run `python -c "import betterleaks; print(betterleaks.scan_string('ordinary text'))"`. The CLI and package version use the Go and Python spellings of the same release.

For a partial upload use **Re-run failed jobs** on the original publishing run. Each upload compares bytes already on the index and resumes with the remaining files. A digest mismatch requires investigation. PyPI release files are immutable. If a new build is needed after a partial release, cut a fresh version. Manual dispatch on main takes the successful upstream Release run ID.
