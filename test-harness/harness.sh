#!/usr/bin/env bash
# harness.sh — Betterleaks backwards-compatibility & performance test harness.
#
# Runs gitleaks v8.30.0 and betterleaks against a set of pinned public repos,
# compares findings for equivalence, and benchmarks performance.
#
# Prerequisites:
#   - gitleaks (v8.30.0)   in PATH or GITLEAKS_BIN
#   - betterleaks binary   in PATH or BETTERLEAKS_BIN
#   - hyperfine            in PATH (for perf benchmarks; skipped if missing)
#   - jq                   in PATH
#   - awk                  for parsing repos.yaml
#   - git
#
# Environment variables:
#   GITLEAKS_BIN       path to gitleaks binary     (default: gitleaks)
#   BETTERLEAKS_BIN    path to betterleaks binary  (default: ../betterleaks)
#   OLD_CONFIG         path to old gitleaks config  (default: ../config/old.toml)
#   NEW_CONFIG         path to new betterleaks config (default: ../config/betterleaks.toml)
#   RUNS               number of hyperfine runs     (default: 5)
#   SKIP_PERF          set to 1 to skip perf phase  (default: 0)
#   SKIP_CLONE         set to 1 to skip clone phase (default: 0)
#
# Usage:
#   bash harness.sh
#   RUNS=3 SKIP_PERF=1 bash harness.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/repos.sh
source "$SCRIPT_DIR/lib/repos.sh"
# shellcheck source=lib/run.sh
source "$SCRIPT_DIR/lib/run.sh"
# shellcheck source=lib/compare.sh
source "$SCRIPT_DIR/lib/compare.sh"
# shellcheck source=lib/perf.sh
source "$SCRIPT_DIR/lib/perf.sh"

# ── Configuration ─────────────────────────────────────────────────────────────

GITLEAKS_VERSION="8.30.0"

export BETTERLEAKS_BIN="${BETTERLEAKS_BIN:-$SCRIPT_DIR/../betterleaks}"
export OLD_CONFIG
OLD_CONFIG="$(cd "$SCRIPT_DIR/.." && pwd)/config/old.toml"
export NEW_CONFIG
NEW_CONFIG="$(cd "$SCRIPT_DIR/.." && pwd)/config/betterleaks.toml"
export FIXTURES_DIR="$SCRIPT_DIR/fixtures"

RESULTS_DIR="$SCRIPT_DIR/results"
RUNS="${RUNS:-5}"
SKIP_PERF="${SKIP_PERF:-0}"
SKIP_CLONE="${SKIP_CLONE:-0}"

mkdir -p "$RESULTS_DIR"

# ── Gitleaks binary ──────────────────────────────────────────────────────────
# Use the official GitHub release binary (built with gore2regex) rather than
# homebrew or other package-manager builds which may use Go's stdlib regex.
# Downloads once into results/.bin/ and reuses on subsequent runs.

ensure_gitleaks() {
  # If the user explicitly set GITLEAKS_BIN, respect that.
  if [ -n "${GITLEAKS_BIN:-}" ]; then
    export GITLEAKS_BIN
    return
  fi

  local bin_dir="$RESULTS_DIR/.bin"
  local bin_path="$bin_dir/gitleaks"

  if [ -x "$bin_path" ] && [ "$("$bin_path" version 2>/dev/null)" = "$GITLEAKS_VERSION" ]; then
    export GITLEAKS_BIN="$bin_path"
    return
  fi

  echo "[setup] downloading gitleaks v${GITLEAKS_VERSION} official release ..."
  mkdir -p "$bin_dir"

  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64)  arch="x64" ;;
    aarch64) arch="arm64" ;;
    arm64)   arch="arm64" ;;
  esac

  local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
  curl -sSfL "$url" | tar xz -C "$bin_dir" gitleaks
  chmod +x "$bin_path"
  export GITLEAKS_BIN="$bin_path"
  echo "[setup] installed gitleaks v${GITLEAKS_VERSION} -> $bin_path"
}

# ── Preflight checks ─────────────────────────────────────────────────────────

check_dependency() {
  if ! command -v "$1" &>/dev/null; then
    echo "ERROR: $1 not found in PATH"
    return 1
  fi
}

echo "=== Preflight ==="
check_dependency jq
check_dependency git

ensure_gitleaks
if [ ! -x "$GITLEAKS_BIN" ] && ! command -v "$GITLEAKS_BIN" &>/dev/null; then
  echo "ERROR: gitleaks not found at $GITLEAKS_BIN"
  exit 1
fi
echo "  gitleaks:     $($GITLEAKS_BIN version 2>/dev/null || echo "$GITLEAKS_BIN") ($GITLEAKS_BIN)"

if [ ! -x "$BETTERLEAKS_BIN" ] && ! command -v "$BETTERLEAKS_BIN" &>/dev/null; then
  echo "ERROR: betterleaks not found at $BETTERLEAKS_BIN"
  echo "  hint: run 'make betterleaks' from the project root first"
  exit 1
fi
echo "  betterleaks:  $($BETTERLEAKS_BIN version 2>/dev/null || echo "$BETTERLEAKS_BIN")"

HAS_HYPERFINE=1
if ! command -v hyperfine &>/dev/null; then
  echo "  hyperfine:    NOT FOUND (perf benchmarks will be skipped)"
  HAS_HYPERFINE=0
else
  echo "  hyperfine:    $(hyperfine --version)"
fi

echo "  old config:   $OLD_CONFIG"
echo "  new config:   $NEW_CONFIG"
echo "  runs:         $RUNS"
echo ""

# ── Phase 1: Clone repos ─────────────────────────────────────────────────────

if [ "$SKIP_CLONE" -ne 1 ]; then
  echo "=== Phase 1: Clone repos ==="
  clone_repos "$RESULTS_DIR/.repos"
  echo ""
fi

# ── Phase 2: Scan ────────────────────────────────────────────────────────────

echo "=== Phase 2: Scan ==="

scan_repo_mode() {
  local repo="$1"
  local repo_dir="$2"
  local mode="$3"
  local out="$RESULTS_DIR/$repo"
  mkdir -p "$out"

  echo ""
  echo "── $repo / $mode ──"

  # A: gitleaks baseline
  run_scan "$GITLEAKS_BIN" "$mode" "$repo_dir" "$OLD_CONFIG" \
    "" "$out/A-gitleaks-${mode}.json"

  # B: betterleaks, old config, legacy output
  run_scan "$BETTERLEAKS_BIN" "$mode" "$repo_dir" "$OLD_CONFIG" \
    "--legacy" "$out/B-betterleaks-legacy-${mode}.json"

  # C: betterleaks, resources config, legacy output
  run_scan "$BETTERLEAKS_BIN" "$mode" "$repo_dir" "$NEW_CONFIG" \
    "--legacy" "$out/C-betterleaks-resources-legacy-${mode}.json"

  # D: betterleaks, resources config, new output
  run_scan "$BETTERLEAKS_BIN" "$mode" "$repo_dir" "$NEW_CONFIG" \
    "" "$out/D-betterleaks-resources-${mode}.json"
}

iter_repos "$RESULTS_DIR/.repos" scan_repo_mode
echo ""

# ── Phase 3: Compare ─────────────────────────────────────────────────────────

echo "=== Phase 3: Compare ==="

compat_fail=0

compare_repo_mode() {
  local repo="$1"
  local repo_dir="$2"
  local mode="$3"
  local out="$RESULTS_DIR/$repo"

  echo ""
  echo "── $repo / $mode ──"

  # A vs B: old config compat (both use gitleaks/legacy format)
  echo "  A vs B (old config, legacy output):"
  if ! compare_reports \
    "$out/A-gitleaks-${mode}.json" "gitleaks" \
    "$out/B-betterleaks-legacy-${mode}.json" "legacy" \
    "$repo" "$mode"; then
    compat_fail=1
  fi

  # A vs C: resources config compat (both in legacy format)
  echo "  A vs C (resources config, legacy output):"
  if ! compare_reports \
    "$out/A-gitleaks-${mode}.json" "gitleaks" \
    "$out/C-betterleaks-resources-legacy-${mode}.json" "legacy" \
    "$repo" "$mode"; then
    compat_fail=1
  fi

  # C vs D: legacy vs new output (should be same findings, different format)
  echo "  C vs D (resources config, legacy vs new output):"
  if ! compare_reports \
    "$out/C-betterleaks-resources-legacy-${mode}.json" "legacy" \
    "$out/D-betterleaks-resources-${mode}.json" "betterleaks" \
    "$repo" "$mode"; then
    compat_fail=1
  fi
}

iter_repos "$RESULTS_DIR/.repos" compare_repo_mode
echo ""

# ── Phase 4: Performance ─────────────────────────────────────────────────────

perf_warn=0

if [ "$SKIP_PERF" -eq 1 ]; then
  echo "=== Phase 4: Performance (SKIPPED) ==="
elif [ "$HAS_HYPERFINE" -eq 0 ]; then
  echo "=== Phase 4: Performance (SKIPPED — hyperfine not installed) ==="
else
  echo "=== Phase 4: Performance ==="

  bench_repo_mode() {
    local repo="$1"
    local repo_dir="$2"
    local mode="$3"

    echo ""
    if ! run_perf_benchmark "$repo_dir" "$RESULTS_DIR/$repo" "$RUNS" "$mode"; then
      perf_warn=1
    fi
  }

  iter_repos "$RESULTS_DIR/.repos" bench_repo_mode
  echo ""
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo "=== Generating summary ==="
generate_summary "$RESULTS_DIR"

# ── Exit ──────────────────────────────────────────────────────────────────────

echo ""
if [ "$compat_fail" -ne 0 ]; then
  echo "FAIL: compatibility regressions detected"
  exit 1
fi

if [ "$perf_warn" -ne 0 ]; then
  echo "WARN: betterleaks was not faster in all benchmarks (see above)"
fi

echo "PASS: all compatibility checks passed"
