#!/usr/bin/env bash
# perf.sh — benchmark gitleaks vs betterleaks with hyperfine.
#
# Usage:
#   source lib/perf.sh
#   run_perf_benchmark <repo_dir> <output_dir> <runs> <mode>
#   check_perf_results <perf_json>
#   generate_summary   <results_dir>

# run_perf_benchmark runs hyperfine comparing gitleaks and betterleaks for a
# single repo and mode.
#
# Args:
#   $1 — repo directory path
#   $2 — output directory for results
#   $3 — number of hyperfine runs
#   $4 — scan mode: "git" or "dir"
run_perf_benchmark() {
  local repo_dir="$1"
  local out_dir="$2"
  local runs="$3"
  local mode="$4"

  local repo
  repo=$(basename "$repo_dir")
  local perf_json="$out_dir/perf-${mode}.json"

  echo "[perf] benchmarking $repo ($mode mode), $runs runs ..."

  # Build the commands. We discard the report (write to /dev/null on Linux,
  # /dev/null on macOS — both work).
  local gl_cmd="${GITLEAKS_BIN} ${mode} ${repo_dir} -c ${OLD_CONFIG} -r /dev/null -f json --no-banner --exit-code 0"
  local bl_old_cmd="${BETTERLEAKS_BIN} ${mode} ${repo_dir} -c ${OLD_CONFIG} --legacy -r /dev/null -f json --no-banner --exit-code 0"
  local bl_new_cmd="${BETTERLEAKS_BIN} ${mode} ${repo_dir} -c ${NEW_CONFIG} -r /dev/null -f json --no-banner --exit-code 0"

  hyperfine \
    --warmup 1 \
    --runs "$runs" \
    --export-json "$perf_json" \
    --command-name "gitleaks" "$gl_cmd" \
    --command-name "betterleaks-old-config" "$bl_old_cmd" \
    --command-name "betterleaks-resources" "$bl_new_cmd" \
    2>&1

  echo "[perf] results written to $perf_json"
  check_perf_results "$perf_json" "$repo" "$mode"
}

# check_perf_results asserts betterleaks is faster than gitleaks.
# Uses median times from hyperfine's JSON output.
#
# Args:
#   $1 — hyperfine JSON output file
#   $2 — repo name (for display)
#   $3 — mode (for display)
#
# Returns 0 if betterleaks is faster, 1 otherwise (warning only, does not fail harness).
check_perf_results() {
  local perf_json="$1"
  local repo="${2:-unknown}"
  local mode="${3:-unknown}"

  if [ ! -f "$perf_json" ]; then
    echo "[perf] WARNING: $perf_json not found, skipping perf check"
    return 0
  fi

  # Extract median times.
  local gl_median bl_old_median bl_new_median
  gl_median=$(jq '.results[] | select(.command == "gitleaks") | .median' "$perf_json")
  bl_old_median=$(jq '.results[] | select(.command == "betterleaks-old-config") | .median' "$perf_json")
  bl_new_median=$(jq '.results[] | select(.command == "betterleaks-resources") | .median' "$perf_json")

  # Compute speedups.
  local speedup_old speedup_new
  speedup_old=$(echo "$gl_median $bl_old_median" | awk '{printf "%.2f", $1/$2}')
  speedup_new=$(echo "$gl_median $bl_new_median" | awk '{printf "%.2f", $1/$2}')

  echo "  [$repo / $mode]"
  printf "    %-28s %8.3fs (median)\n" "gitleaks:" "$gl_median"
  printf "    %-28s %8.3fs (median)  %sx\n" "betterleaks (old config):" "$bl_old_median" "$speedup_old"
  printf "    %-28s %8.3fs (median)  %sx\n" "betterleaks (resources):" "$bl_new_median" "$speedup_new"

  local rc=0
  if awk "BEGIN {exit !($bl_old_median < $gl_median)}"; then
    echo "    PASS: betterleaks (old config) is ${speedup_old}x faster"
  else
    echo "    WARN: betterleaks (old config) is NOT faster than gitleaks"
    rc=1
  fi

  if awk "BEGIN {exit !($bl_new_median < $gl_median)}"; then
    echo "    PASS: betterleaks (resources) is ${speedup_new}x faster"
  else
    echo "    WARN: betterleaks (resources) is NOT faster than gitleaks"
    rc=1
  fi

  return "$rc"
}

# generate_summary rolls up all per-repo results into a single summary.json.
#
# Args:
#   $1 — results directory
generate_summary() {
  local results_dir="$1"
  local summary="$results_dir/summary.json"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  local gl_version bl_version
  gl_version=$("${GITLEAKS_BIN}" version 2>/dev/null || echo "unknown")
  bl_version=$("${BETTERLEAKS_BIN}" version 2>/dev/null || echo "unknown")

  # Build the repos array by iterating over result directories.
  local repos_json="[]"

  for repo_dir in "$results_dir"/*/; do
    local repo
    repo=$(basename "$repo_dir")
    # Skip the .repos cache directory.
    [ "$repo" = ".repos" ] && continue

    local repo_entry
    repo_entry=$(jq -n --arg name "$repo" '{ name: $name, compat: {}, perf: {} }')

    # Merge compat results for each mode.
    for mode in git dir; do
      local a_file="$repo_dir/A-gitleaks-${mode}.json"
      local b_file="$repo_dir/B-betterleaks-legacy-${mode}.json"
      local c_file="$repo_dir/C-betterleaks-resources-legacy-${mode}.json"

      if [ -f "$a_file" ] && [ -f "$b_file" ]; then
        local a_count b_count
        a_count=$(jq 'length' "$a_file")
        b_count=$(jq 'length' "$b_file")
        repo_entry=$(echo "$repo_entry" | jq \
          --arg mode "$mode" \
          --argjson a "$a_count" \
          --argjson b "$b_count" \
          '.compat[$mode + "_old_config"] = { findings_baseline: $a, findings_candidate: $b }')
      fi

      if [ -f "$a_file" ] && [ -f "$c_file" ]; then
        local a_count c_count
        a_count=$(jq 'length' "$a_file")
        c_count=$(jq 'length' "$c_file")
        repo_entry=$(echo "$repo_entry" | jq \
          --arg mode "$mode" \
          --argjson a "$a_count" \
          --argjson c "$c_count" \
          '.compat[$mode + "_resources_config"] = { findings_baseline: $a, findings_candidate: $c }')
      fi

      # Merge perf results.
      local perf_file="$repo_dir/perf-${mode}.json"
      if [ -f "$perf_file" ]; then
        local gl_med bl_old_med bl_new_med
        gl_med=$(jq '.results[] | select(.command == "gitleaks") | .median' "$perf_file")
        bl_old_med=$(jq '.results[] | select(.command == "betterleaks-old-config") | .median' "$perf_file")
        bl_new_med=$(jq '.results[] | select(.command == "betterleaks-resources") | .median' "$perf_file")

        repo_entry=$(echo "$repo_entry" | jq \
          --arg mode "$mode" \
          --argjson gl "$gl_med" \
          --argjson blo "$bl_old_med" \
          --argjson bln "$bl_new_med" \
          '.perf[$mode] = {
            gitleaks_median_s: $gl,
            betterleaks_old_median_s: $blo,
            betterleaks_resources_median_s: $bln,
            speedup_old: (($gl / $blo * 100 | round) / 100),
            speedup_resources: (($gl / $bln * 100 | round) / 100)
          }')
      fi
    done

    repos_json=$(echo "$repos_json" | jq --argjson entry "$repo_entry" '. + [$entry]')
  done

  jq -n \
    --arg ts "$timestamp" \
    --arg glv "$gl_version" \
    --arg blv "$bl_version" \
    --argjson repos "$repos_json" \
    '{
      timestamp: $ts,
      gitleaks_version: $glv,
      betterleaks_version: $blv,
      repos: $repos
    }' > "$summary"

  echo ""
  echo "=== Summary ==="
  jq '.' "$summary"
  echo ""
  echo "Written to $summary"
}
