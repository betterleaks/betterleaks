#!/usr/bin/env bash
# repos.sh — clone and cache test target repos.
#
# Requires: git, awk
#
# Usage:
#   source lib/repos.sh
#   clone_repos /path/to/repos_dir

# parse_repos prints "url ref mode1,mode2" lines from fixtures/repos.yaml.
# Pure awk parser — no Python/yq dependency needed.
# Handles the simple YAML structure used in repos.yaml.
parse_repos() {
  local yaml_file="$1"
  awk '
    /^- url:/ {
      if (url != "") {
        if (modes == "") modes = "git,dir"
        print url, ref, modes
      }
      url = $NF; ref = ""; modes = ""
    }
    /^  ref:/ { ref = $NF }
    /^  modes:/ {
      # modes: [git, dir] — strip brackets, spaces, quotes
      gsub(/.*\[/, ""); gsub(/\].*/, ""); gsub(/ /, ""); gsub(/"/, "")
      modes = $0
    }
    END {
      if (url != "") {
        if (modes == "") modes = "git,dir"
        print url, ref, modes
      }
    }
  ' "$yaml_file"
}

# clone_repos clones every repo in the fixtures file into the target directory.
# Skips repos that are already cloned at the correct ref.
#
# Args:
#   $1 — destination directory (e.g. results/.repos)
clone_repos() {
  local dest_root="$1"
  local yaml_file="${FIXTURES_DIR:-$SCRIPT_DIR/fixtures}/repos.yaml"

  mkdir -p "$dest_root"

  while IFS=' ' read -r url ref modes; do
    local name
    name=$(basename "$url" .git)
    local dest="$dest_root/$name"

    if [ -d "$dest/.git" ]; then
      # Already cloned — verify we're at the right ref.
      local current_sha
      current_sha=$(git -C "$dest" rev-parse HEAD 2>/dev/null || echo "")
      if [ "$current_sha" = "$ref" ]; then
        echo "[repos] $name: already at $ref, skipping"
        continue
      fi
      echo "[repos] $name: fetching and checking out $ref"
      git -C "$dest" fetch origin "$ref" --quiet
      git -C "$dest" checkout "$ref" --quiet
      continue
    fi

    # Determine clone depth.  git-mode needs full history; dir-only can shallow clone.
    if [[ "$modes" == *"git"* ]]; then
      echo "[repos] $name: full clone (git mode) ..."
      git clone --quiet "$url" "$dest"
    else
      echo "[repos] $name: shallow clone (dir-only) ..."
      git clone --quiet --depth 1 "$url" "$dest"
    fi

    git -C "$dest" checkout --quiet "$ref"
    echo "[repos] $name: checked out $ref"
  done < <(parse_repos "$yaml_file")
}

# iter_repos calls a callback for each repo/mode combination.
#
# Args:
#   $1 — repos directory (e.g. results/.repos)
#   $2 — callback function name, called as: callback <repo_name> <repo_dir> <mode>
iter_repos() {
  local repos_dir="$1"
  local callback="$2"
  local yaml_file="${FIXTURES_DIR:-$SCRIPT_DIR/fixtures}/repos.yaml"

  while IFS=' ' read -r url ref modes; do
    local name
    name=$(basename "$url" .git)
    local repo_dir="$repos_dir/$name"

    IFS=',' read -ra mode_arr <<< "$modes"
    for mode in "${mode_arr[@]}"; do
      "$callback" "$name" "$repo_dir" "$mode"
    done
  done < <(parse_repos "$yaml_file")
}
