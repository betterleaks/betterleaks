# Advanced Scanning Guide

Use `--help` for full flag descriptions. This page is for patterns.

## Pick a target

| Want to scan | Use |
| :--- | :--- |
| Files on disk | `betterleaks dir` |
| Git history | `betterleaks git` |
| Staged or pre-commit diffs | `betterleaks git --pre-commit [--staged]` |
| GitHub repos, Issues, PRs, Actions, Releases, Discussions, Gists | `betterleaks github <url>` |
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

`github` takes a target URL. Owner and repo targets scan git history by default; specific resource URLs scan the matching resource plus associated comments or assets by default. Use `--include` to add resource types and `--exclude` to skip types.

Set `GITHUB_TOKEN` in the environment before running these examples.

### Resource types

| Type | Description |
| :--- | :--- |
| `repos` | Git repository history (default) |
| `forks` | Include forked repositories |
| `prs` | Pull request descriptions |
| `pr-comments` | Comments on pull requests (auto-included with `prs`) |
| `issues` | Issue descriptions |
| `issue-comments` | Comments on issues  (auto-included with `issues`) |
| `actions` | Action run console output |
| `action-artifacts` | Artifacts created by action runs |
| `discussions` | Discussion threads and replies |
| `releases` | Release descriptions |
| `release-assets` | Downloadable release assets and source archives (auto-included with `releases`) |
| `gists` | Gist file contents (all public gists for user targets, or one gist URL) |

### Target selection

```sh
# scan a repo's git history
betterleaks github https://github.com/betterleaks/betterleaks

# scan all repos under an org
betterleaks github https://github.com/my-company

# scan all repos under a user
betterleaks github https://github.com/octocat

# exclude forks and repo globs
betterleaks github \
	--include=forks \
	--exclude-repo 'my-company/*-archive' \
	--exclude-repo 'my-company/playground-*' \
	https://github.com/my-company

# skip repo git history, scan only API resources
betterleaks github \
	--include=issues,prs,issue-comments,pr-comments \
	--exclude=repos \
	https://github.com/my-company
```

### Issues, PRs, comments

```sh
betterleaks github \
	--include=issues,prs,issue-comments,pr-comments \
	--since 2026-01-01 \
	https://github.com/my-company/backend

betterleaks github \
	--include=issues,prs,issue-comments \
	--since 2026-01-01 \
	--until 2026-04-01 \
	https://github.com/my-company
```

### Actions

```sh
# workflow logs
betterleaks github \
	--include=actions \
	https://github.com/my-company/backend

# only one workflow, recent runs only
betterleaks github \
	--include=actions \
	--actions-workflow ci.yml \
	--since 2026-01-01 \
	https://github.com/my-company/backend

# include workflow artifacts
betterleaks github \
	--include=actions,action-artifacts \
	https://github.com/my-company/backend
```

### Discussions, releases, gists

```sh
# discussions (comments included automatically)
betterleaks github \
	--include=discussions \
	https://github.com/my-company/backend

# releases and release assets
betterleaks github \
	--include=releases \
	https://github.com/my-company/backend

# releases, but skip downloadable assets
betterleaks github \
	--include=releases \
	--exclude=release-assets \
	https://github.com/my-company/backend

# user gists
betterleaks github \
	--include=gists \
	https://github.com/octocat
```

### Single GitHub resource

```sh
# pull request
betterleaks github https://github.com/my-company/backend/pull/1234

# issue
betterleaks github https://github.com/my-company/backend/issues/99

# discussion
betterleaks github https://github.com/my-company/backend/discussions/45

# release tag
betterleaks github https://github.com/my-company/backend/releases/tag/v1.2.3

# actions run
betterleaks github https://github.com/my-company/backend/actions/runs/123456789

# gist
betterleaks github https://gist.github.com/octocat/aaaaaaaaaaaaaaaaaaaa
```

### GitHub Enterprise

```sh
betterleaks github https://github.example.com/platform-team
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

