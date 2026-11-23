# Betterleaks for npm

This package installs the Betterleaks CLI. The launcher forwards arguments,
standard input, output and the CLI exit status. npm selects a binary using the
OS and CPU declared by six exact-version optional dependencies.

## Prepare a release

From the repository root, use the existing GoReleaser build. For a rehearsal:

```sh
goreleaser build --snapshot --clean
npm --prefix bindings/node run pack:cli
npm --prefix bindings/node run test:pack
```

The packer reads `dist/artifacts.json` and the engine version in
`dist/metadata.json`. It writes seven tarballs under `dist/npm/<version>/`.
The release workflow attaches them as a workflow artifact for inspection.

For the first npm release, use a real release candidate and an npm account with
publish access to the bare `betterleaks` name and the `@betterleaks` scope.
Publish the six platform tarballs with `npm publish <tarball> --access public
--tag next`, then the launcher with the same tag. Try `npx betterleaks@next
--version` and a scan before publishing a stable version under `latest`.

Once published, users can install the CLI with `npm install --save-dev
betterleaks` or run it with `npx betterleaks`. The platform packages contain
the binaries, so installation also works with `--ignore-scripts`.
