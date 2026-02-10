#!/usr/bin/env bash
# run.sh — execute a single scan and capture the JSON report.
#
# Usage:
#   source lib/run.sh
#   run_scan <binary> <mode> <repo_dir> <config> <extra_flags> <output_json>

# run_scan executes a gitleaks/betterleaks scan and writes the JSON report.
#
# Both gitleaks and betterleaks exit non-zero when leaks are found.
# That's expected — we only treat it as a real failure if the binary crashes
# (segfault, missing binary, etc.).
#
# Args:
#   $1 — binary path (gitleaks or betterleaks)
#   $2 — scan mode: "git" or "dir"
#   $3 — target repo/directory path
#   $4 — config file path
#   $5 — extra flags (e.g. "--legacy"), can be empty string
#   $6 — output JSON report path
run_scan() {
  local bin="$1"
  local mode="$2"
  local target="$3"
  local config="$4"
  local extra_flags="$5"
  local output="$6"

  local bin_name
  bin_name=$(basename "$bin")

  local label="${bin_name}/${mode}"
  [ -n "$extra_flags" ] && label="${label} ${extra_flags}"

  echo "[scan] ${label} -> $(basename "$output")"

  local cmd=("$bin" "$mode" "$target"
    --config "$config"
    --report-path "$output"
    --report-format json
    --no-banner
    --exit-code 0
  )

  # Append extra flags (word-split intentional).
  if [ -n "$extra_flags" ]; then
    # shellcheck disable=SC2206
    cmd+=($extra_flags)
  fi

  local rc=0
  "${cmd[@]}" 2>/dev/null || rc=$?

  # exit-code 0 means "don't fail on leaks found", so any non-zero here
  # is an actual error (crash, bad config, etc.).
  if [ "$rc" -ne 0 ]; then
    echo "[scan] ERROR: ${label} exited with code $rc"
    # Write an empty array so downstream comparison can still run and report
    # the missing findings rather than crashing on a missing file.
    echo "[]" > "$output"
    return 1
  fi

  # If the tool produced no findings it may not write a file at all.
  if [ ! -f "$output" ]; then
    echo "[]" > "$output"
  fi

  local count
  count=$(jq '(. // []) | length' "$output")
  echo "[scan] ${label}: $count findings"
}
