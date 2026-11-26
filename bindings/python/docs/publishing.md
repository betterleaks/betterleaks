# Publishing Guide & PyPI Trusted Publishing Setup (`betterleaks`)

`betterleaks` is a pure-Python distribution depending on [`betterleaks-cli`](../cli/docs/publishing.md) (all platforms) and [`betterleaks-sdk`](../sdk/docs/publishing.md) (`sys_platform != 'win32'`).

Publish `betterleaks-cli` and `betterleaks-sdk` first for a given minor/major series so `betterleaks`'s dependencies resolve immediately on PyPI.

- **PyPI Project Name**: `betterleaks`
- **Workflow name**: `python-release.yml`
- **Environment name**: `pypi`
- **Trigger**: Push tag `python-v*` (e.g. `python-v2.0.0`) or `workflow_dispatch` with `version`.
