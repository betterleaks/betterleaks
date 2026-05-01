# Advanced Scanning Guide

Use `--help` for full flag descriptions. This page is for patterns.

## Pick a target

| Want to scan | Use |
| :--- | :--- |
| Files on disk | `betterleaks dir` |
| Git history | `betterleaks git` |
| Staged or pre-commit diffs | `betterleaks git --pre-commit [--staged]` |
| GitHub repos plus Issues, PRs, Actions, Releases, Discussions, or Gists | `betterleaks github` |
| Piped content | `betterleaks stdin` |

---

## `dir`

Use `dir` for current filesystem state.

```sh
# current directory
betterleaks dir .

# multiple paths
betterleaks dir services/api infra/terraform

# verbose triage with context
betterleaks dir . -v --match-context 3L

# follow file symlinks
betterleaks dir /mnt/data --follow-symlinks

# skip large files
betterleaks dir . --max-target-megabytes 20

# scan inside archives
betterleaks dir ./release-bundles --max-archive-depth 2

# JSON report
betterleaks dir . --report-path findings.json --report-format json

# SARIF for code scanning platforms
betterleaks dir . --report-path findings.sarif --report-format sarif
```

---

## `git`

Use `git` for history and diffs.

```sh
# full repo history
betterleaks git .

# parallel history scan
betterleaks git . --git-workers 8

# custom git log scope
betterleaks git . --log-opts="--all --since='90 days ago'"

# current working tree diff
betterleaks git . --pre-commit

# staged diff only
betterleaks git . --pre-commit --staged

# generate platform links in findings
betterleaks git . --platform github

# history scan with JSON output
betterleaks git . --git-workers 8 --report-path findings.json --report-format json
```

---

## `github`

`github` scans selected repos' git history by default. Extra flags add more GitHub surfaces.

Set `GITHUB_TOKEN` in the environment before running these examples.

### Repo selection

```sh
# one org
betterleaks github --org betterleaks

# one user
betterleaks github --user octocat

# explicit repos
betterleaks github \
	--repo betterleaks/betterleaks \
	--repo octo-org/example-service

# exclude forks and repo globs
betterleaks github \
	--org my-company \
	--exclude-forks \
	--exclude-repo 'my-company/*-archive' \
	--exclude-repo 'my-company/playground-*'

# auxiliary GitHub surfaces only, no repo git history
betterleaks github \
	--org my-company \
	--issues --prs --comments \
	--no-git
```

### Issues, PRs, comments

```sh
betterleaks github \
	--repo my-company/backend \
	--issues --prs --comments \
	--issues-max 200 \
	--comments-max 100

betterleaks github \
	--org my-company \
	--issues --prs --comments \
	--since 2026-01-01 \
	--until 2026-04-01
```

### Actions

```sh
# workflow logs
betterleaks github \
	--repo my-company/backend \
	--actions

# only one workflow, recent runs only
betterleaks github \
	--repo my-company/backend \
	--actions \
	--actions-workflow ci.yml \
	--actions-max-age 168h \
	--actions-max-runs 25

# include workflow artifacts
betterleaks github \
	--repo my-company/backend \
	--actions \
	--actions-artifacts
```

### Discussions, releases, gists

```sh
# discussions
betterleaks github \
	--repo my-company/backend \
	--discussions --comments

# releases and release assets
betterleaks github \
	--repo my-company/backend \
	--releases

# releases, but skip artifacts
betterleaks github \
	--repo my-company/backend \
	--releases --no-release-artifacts

# user gists
betterleaks github \
	--user octocat \
	--gists
```

### Single GitHub resource

```sh
# pull request
betterleaks github \
	--resource-url https://github.com/my-company/backend/pull/1234

# issue
betterleaks github \
	--resource-url https://github.com/my-company/backend/issues/99

# discussion
betterleaks github \
	--resource-url https://github.com/my-company/backend/discussions/45

# release tag
betterleaks github \
	--resource-url https://github.com/my-company/backend/releases/tag/v1.2.3

# actions run
betterleaks github \
	--resource-url https://github.com/my-company/backend/actions/runs/123456789

# gist
betterleaks github \
	--resource-url https://gist.github.com/octocat/aaaaaaaaaaaaaaaaaaaa
```

### GitHub Enterprise

```sh
betterleaks github \
	--org platform-team \
	--base-url https://github.example.com/
```

---

## `stdin`

Use `stdin` for generated or piped content.

```sh
# file through a pipe
cat .env | betterleaks stdin

# generated JSON
terraform output -json | betterleaks stdin -v

# decompressed stream
curl -sL https://example.com/blob.txt.gz | gunzip | betterleaks stdin

# JSON report to stdout
some-command | betterleaks stdin --report-path - --report-format json
```

---

## Handy shared patterns

```sh
# use a specific config
betterleaks dir . --config .betterleaks.toml

# only run selected rules
betterleaks git . --enable-rule github-pat --enable-rule aws-access-key

# use a baseline
betterleaks git . --baseline-path findings.json

# enable live validation
betterleaks dir . --validation --validation-status valid,unknown

# redact output
betterleaks git . -v --redact

# custom template report
betterleaks dir . \
	--report-path report.txt \
	--report-format template \
	--report-template report_templates/basic.tmpl

# show clipped context in verbose mode
betterleaks dir . -v --match-context 5L,40C

# scan archives and decoded content together
betterleaks dir ./artifacts --max-archive-depth 2 --max-decode-depth 5
```

---

## Related docs

- [docs/config.md](config.md)