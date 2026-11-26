# Publishing Guide & PyPI Trusted Publishing Setup (`betterleaks-sdk`)

`betterleaks-sdk` is published to **PyPI** via **OpenID Connect (OIDC) Trusted Publishing** with **PEP 740 digital attestations**.

- **PyPI Project Name**: `betterleaks-sdk`
- **Workflow name**: `python-sdk-release.yml`
- **Environment name**: `pypi-sdk`
- **Trigger**: Push tag `sdk-v*` (e.g. `sdk-v2.0.0`) or `workflow_dispatch` with `version`.
