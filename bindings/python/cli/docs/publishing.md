# Publishing Guide & PyPI Trusted Publishing Setup (`betterleaks-cli`)

`betterleaks-cli` is published to **PyPI** via **OpenID Connect (OIDC) Trusted Publishing** with **PEP 740 digital attestations**.

- **PyPI Project Name**: `betterleaks-cli`
- **Workflow name**: `python-cli-release.yml`
- **Environment name**: `pypi-cli`
- **Trigger**: Push tag `cli-v*` (e.g. `cli-v2.0.0`) or `workflow_dispatch` with `version`.
