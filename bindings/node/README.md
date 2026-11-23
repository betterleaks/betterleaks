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

The tag's successful **Release** workflow produces the `npm-cli-<tag>` artifact
with seven tarballs, `SHA256SUMS`, and a Sigstore bundle. Use an npm account
with publish access to `betterleaks` and the `@betterleaks` scope.

Set `TAG` to the exact release-candidate tag and `RUN_ID` to its GitHub Actions
run ID. Run this block in Bash with GitHub CLI, Cosign 3, and npm installed.
It downloads into a fresh directory, verifies the signing workflow and tag,
checks all seven tarballs, and publishes the platform packages before the launcher.

```bash
(
  set -euo pipefail
  : "${TAG:?set TAG to the release-candidate tag}" "${RUN_ID:?set RUN_ID to its Release run ID}"
  [[ "$TAG" =~ ^v2\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]
  version="${TAG#v}"
  cd "$(mktemp -d)"
  gh run download "$RUN_ID" --repo betterleaks/betterleaks --name "npm-cli-$TAG"
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
  files=(betterleaks-cli-{darwin,linux,win32}-{arm64,x64}-"$version".tgz "betterleaks-$version.tgz")
  # Compare exactly the files to be published, including their names.
  shasum -a 256 -- "${files[@]}" | LC_ALL=C sort > actual
  LC_ALL=C sort SHA256SUMS > expected
  cmp expected actual
  for file in "${files[@]}"; do
    npm publish "./$file" --registry=https://registry.npmjs.org --access public --tag next --ignore-scripts
  done
)
```

Try `npx betterleaks@next --version` and a scan before promoting a stable
release to `latest`.

Once published, users can install the CLI with `npm install --save-dev
betterleaks` or run it with `npx betterleaks`. The platform packages contain
the binaries, so installation also works with `--ignore-scripts`.
