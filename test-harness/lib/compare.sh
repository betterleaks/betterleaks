#!/usr/bin/env bash
# compare.sh — normalize and diff two JSON finding reports.
#
# Usage:
#   source lib/compare.sh
#   compare_reports <baseline.json> <baseline_fmt> <candidate.json> <candidate_fmt> [<repo> <mode>]
#
# Formats: "gitleaks" (or "legacy") — File/Commit at top level
#          "betterleaks"            — Metadata.path / Metadata.commit_sha

# normalize transforms a findings JSON array into a sorted canonical form.
# Each finding becomes:
#   { key: "<rule>:<commit>:<file>:<line>:<secret_sha>", rule, file, commit, line, match }
#
# Args:
#   $1 — input JSON file
#   $2 — format: "gitleaks", "legacy", or "betterleaks"
#   stdout — normalized JSON array
normalize() {
  local file="$1"
  local fmt="$2"

  jq --arg fmt "$fmt" '
    # Handle null/empty input (no findings produced).
    (. // []) |

    def secret_hash:
      # jq does not have sha256, so we use a sortable stand-in:
      # base64-encode the secret for stable comparison across tools.
      # This is fine — we never publish these artifacts.
      @base64;

    def extract_file:
      if $fmt == "betterleaks" then
        .Metadata.path // ""
      else
        .File // ""
      end;

    def extract_commit:
      if $fmt == "betterleaks" then
        .Metadata.commit_sha // ""
      else
        .Commit // ""
      end;

    def extract_author:
      if $fmt == "betterleaks" then
        .Metadata.author_name // ""
      else
        .Author // ""
      end;

    def extract_email:
      if $fmt == "betterleaks" then
        .Metadata.author_email // ""
      else
        .Email // ""
      end;

    def extract_date:
      if $fmt == "betterleaks" then
        .Metadata.commit_date // ""
      else
        .Date // ""
      end;

    def extract_message:
      if $fmt == "betterleaks" then
        .Metadata.commit_message // ""
      else
        .Message // ""
      end;

    [
      .[] | {
        rule:        .RuleID,
        file:        extract_file,
        commit:      extract_commit,
        line:        .StartLine,
        secret_hash: (.Secret | secret_hash),
        match:       .Match,
        author:      extract_author,
        email:       extract_email,
        date:        extract_date,
        message:     extract_message,
        key:         (
          .RuleID + ":" +
          extract_commit + ":" +
          extract_file + ":" +
          (.StartLine | tostring) + ":" +
          (.Secret | secret_hash)
        )
      }
    ] | sort_by(.key)
  ' "$file"
}

# load_known_deltas returns a newline-separated list of "rule:abs_delta" for a
# given repo and mode from fixtures/known-deltas.yaml.
#
# Args:
#   $1 — repo name
#   $2 — mode (git or dir)
#   stdout — lines of "rule delta" (e.g. "aws-access-token -1")
load_known_deltas() {
  local repo="$1"
  local mode="$2"
  local deltas_file="${FIXTURES_DIR:-$SCRIPT_DIR/fixtures}/known-deltas.yaml"

  if [ ! -f "$deltas_file" ]; then
    return
  fi

  # Simple awk parser for the known-deltas YAML.
  awk -v target_repo="$repo" -v target_mode="$mode" '
    /^- repo:/ {
      r = $NF; m = ""; rule = ""; delta = ""
    }
    /^  mode:/ { m = $NF }
    /^  rule:/ { rule = $NF }
    /^  delta:/ { delta = $NF }
    /^  reason:/ || /^-/ || /^$/ {
      if (r == target_repo && m == target_mode && rule != "" && delta != "") {
        print rule, delta
      }
      if (/^-/ && !/^- repo:/) { r = ""; m = ""; rule = ""; delta = "" }
    }
    END {
      if (r == target_repo && m == target_mode && rule != "" && delta != "") {
        print rule, delta
      }
    }
  ' "$deltas_file"
}

# is_known_delta checks if a set of missing findings for a rule are accounted
# for by a known delta.
#
# Args:
#   $1 — repo name
#   $2 — mode
#   $3 — rule ID
#   $4 — number of missing findings for this rule
#
# Returns 0 if accounted for, 1 otherwise.
is_known_delta() {
  local repo="$1"
  local mode="$2"
  local rule="$3"
  local missing_for_rule="$4"

  while IFS=' ' read -r known_rule known_delta; do
    if [ "$known_rule" = "$rule" ]; then
      # delta is negative (betterleaks has fewer). The number of missing
      # findings should match abs(delta).
      local abs_delta=${known_delta#-}
      if [ "$missing_for_rule" -le "$abs_delta" ]; then
        return 0
      fi
    fi
  done < <(load_known_deltas "$repo" "$mode")

  return 1
}

# compare_reports diffs two normalized reports and prints a summary.
#
# Returns 0 if findings are equivalent (or differences are known deltas), 1
# if there are unexplained missing findings.
# Extra findings in the candidate produce warnings but don't fail.
#
# Args:
#   $1 — baseline JSON file
#   $2 — baseline format
#   $3 — candidate JSON file
#   $4 — candidate format
#   $5 — repo name (optional, for known-deltas lookup)
#   $6 — mode (optional, for known-deltas lookup)
compare_reports() {
  local baseline_file="$1"
  local baseline_fmt="$2"
  local candidate_file="$3"
  local candidate_fmt="$4"
  local repo="${5:-}"
  local mode="${6:-}"

  local baseline_norm candidate_norm
  baseline_norm=$(normalize "$baseline_file" "$baseline_fmt")
  candidate_norm=$(normalize "$candidate_file" "$candidate_fmt")

  local baseline_count candidate_count
  baseline_count=$(echo "$baseline_norm" | jq 'length')
  candidate_count=$(echo "$candidate_norm" | jq 'length')

  # Extract key sets.
  local baseline_keys candidate_keys
  baseline_keys=$(echo "$baseline_norm" | jq -r '.[].key' | sort)
  candidate_keys=$(echo "$candidate_norm" | jq -r '.[].key' | sort)

  # Compute diffs.
  local missing extra
  missing=$(comm -23 <(echo "$baseline_keys") <(echo "$candidate_keys"))
  extra=$(comm -13 <(echo "$baseline_keys") <(echo "$candidate_keys"))

  local missing_count extra_count
  missing_count=$(echo "$missing" | grep -c . || true)
  extra_count=$(echo "$extra" | grep -c . || true)

  # Print summary.
  local label
  label="$(basename "$baseline_file") vs $(basename "$candidate_file")"

  echo "  [$label]"
  echo "    baseline: $baseline_count findings"
  echo "    candidate: $candidate_count findings"

  # Check missing findings against known deltas.
  local unexplained_missing=0
  if [ "$missing_count" -gt 0 ]; then
    echo "    MISSING ($missing_count findings in baseline but not in candidate):"

    # Group missing by rule.
    local missing_rules
    missing_rules=$(echo "$missing" | awk -F: '{print $1}' | sort | uniq -c | awk '{print $2, $1}')

    while IFS=' ' read -r rule count; do
      [ -z "$rule" ] && continue

      # Show the missing findings for this rule.
      echo "$missing" | grep "^${rule}:" | while IFS= read -r key; do
        local detail
        detail=$(echo "$baseline_norm" | jq -r --arg k "$key" '.[] | select(.key == $k) | "      \(.rule) \(.file):\(.line)"')
        echo "$detail"
      done

      # Check if this is a known delta.
      if [ -n "$repo" ] && [ -n "$mode" ] && is_known_delta "$repo" "$mode" "$rule" "$count"; then
        echo "      ^ known delta ($count finding(s) for $rule)"
      else
        unexplained_missing=$((unexplained_missing + count))
      fi
    done <<< "$missing_rules"
  fi

  if [ "$extra_count" -gt 0 ]; then
    echo "    EXTRA ($extra_count findings in candidate but not in baseline):"
    echo "$extra" | head -20 | while IFS= read -r key; do
      local detail
      detail=$(echo "$candidate_norm" | jq -r --arg k "$key" '.[] | select(.key == $k) | "      \(.rule) \(.file):\(.line)"')
      echo "$detail"
    done
    if [ "$extra_count" -gt 20 ]; then
      echo "      ... and $((extra_count - 20)) more"
    fi
  fi

  # Check field-level mismatches for findings that share the same key.
  # Fields already encoded in the key: RuleID, File, Commit, StartLine, Secret.
  # Additional fields compared here: Match, Author, Email, Date, Message.
  local common_keys mismatch_count
  common_keys=$(comm -12 <(echo "$baseline_keys") <(echo "$candidate_keys"))
  mismatch_count=0

  if [ -n "$common_keys" ]; then
    while IFS= read -r key; do
      [ -z "$key" ] && continue

      local diffs=""
      for field in match author email date message; do
        local b_val c_val
        b_val=$(echo "$baseline_norm" | jq -r --arg k "$key" --arg f "$field" '[.[] | select(.key == $k)][0][$f]')
        c_val=$(echo "$candidate_norm" | jq -r --arg k "$key" --arg f "$field" '[.[] | select(.key == $k)][0][$f]')

        if [ "$b_val" != "$c_val" ]; then
          [ -n "$diffs" ] && diffs="$diffs, "
          diffs="${diffs}${field}"
        fi
      done

      if [ -n "$diffs" ]; then
        if [ "$mismatch_count" -eq 0 ]; then
          echo "    FIELD MISMATCHES (same key, different values):"
        fi
        local rule file line
        rule=$(echo "$key" | cut -d: -f1)
        file=$(echo "$baseline_norm" | jq -r --arg k "$key" '[.[] | select(.key == $k)][0].file')
        line=$(echo "$baseline_norm" | jq -r --arg k "$key" '[.[] | select(.key == $k)][0].line')
        echo "      $rule $file:$line — differs in: $diffs"
        mismatch_count=$((mismatch_count + 1))
      fi
    done <<< "$common_keys"
  fi

  if [ "$missing_count" -eq 0 ] && [ "$extra_count" -eq 0 ] && [ "$mismatch_count" -eq 0 ]; then
    echo "    PASS: findings match exactly"
    return 0
  elif [ "$unexplained_missing" -eq 0 ] && [ "$mismatch_count" -eq 0 ]; then
    if [ "$missing_count" -gt 0 ]; then
      echo "    PASS: all $missing_count missing finding(s) are known deltas"
    fi
    if [ "$extra_count" -gt 0 ]; then
      echo "    WARN: candidate has $extra_count extra findings"
    fi
    return 0
  else
    if [ "$unexplained_missing" -gt 0 ]; then
      echo "    FAIL: $unexplained_missing unexplained missing finding(s)"
    fi
    if [ "$mismatch_count" -gt 0 ]; then
      echo "    FAIL: $mismatch_count field mismatch(es) in matched findings"
    fi
    return 1
  fi
}
