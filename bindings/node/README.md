# Betterleaks for npm

This package installs the Betterleaks CLI. The launcher forwards arguments,
standard input, output and the CLI exit status. npm selects a binary using the
OS and CPU declared by six exact-version optional dependencies.

## Prepare a release

To rehearse from the repository root, run

```sh
goreleaser build --snapshot --clean
npm --prefix bindings/node run pack:cli
python3 bindings/node/scripts/verify-pack.py
npm --prefix bindings/node run test:pack
```

The packer reads `dist/artifacts.json` and the engine version in
`dist/metadata.json`. It writes seven tarballs under `dist/npm/<version>/`.
CI checks the exact files and manifest of each package, compares the six
executables with the GoReleaser outputs, and tests offline installation.

## Verify and publish a release candidate

**Publish npm RC** runs on `main` after a successful **Release** for a
`v2.X.Y-rc.N` tag. It downloads the signed artifact from that run, checks the
Cosign identity against the tag and commit, and verifies all seven file hashes.
It publishes the platform packages first and the launcher last, all under
`next`. Stable releases and `latest` are managed separately.

The workflow authenticates to npm with GitHub OIDC. To retry while the signed
artifact is available, run **Publish npm RC** on `main` with the original
**Release** run ID. It skips versions with matching bytes and stops if a
published version has different contents or publishing would move `next` backwards.

Install the candidate with
`npm install --save-dev betterleaks@next` or run it with `npx betterleaks@next`. The platform packages
contain the binaries, so installation also works with `--ignore-scripts`.
