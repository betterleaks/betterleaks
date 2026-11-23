#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# The builder runs on the host. Select a cross target with -target, not GOOS.
exec env GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
    go run ./bindings/cmd/build-native "$@"
