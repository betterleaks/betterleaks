# Advanced Scanning Guide

Use `--help` for full flag descriptions. This page is for patterns.

## Pick a target

| Want to scan | Use |
| :--- | :--- |
| Files on disk | `betterleaks dir` |
| Git history | `betterleaks git` |
| Staged or pre-commit diffs | `betterleaks git --pre-commit [--staged]` |
| GitHub repos, Issues, PRs, Actions, Releases, Discussions, Gists | `betterleaks github <url>` |
| GitLab projects, Issues, MRs, Snippets, Releases, CI jobs/artifacts | `betterleaks gitlab <url>` |
| Hugging Face models, datasets, Spaces, discussions, PRs, buckets | `betterleaks huggingface <url>` or `betterleaks hf <url>` |
| S3 (and S3-compatible: R2, MinIO, etc.) | `betterleaks s3 <url>` |
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

## `gitlab`

`gitlab` takes a target URL. Project, group, and user targets scan git history by default; specific resource URLs scan the matching resource plus associated comments or assets by default. Use `--include` to add resource types and `--exclude` to skip types.

Set `GITLAB_TOKEN` in the environment before running these examples. Public project git history can be scanned without a token, but group/user enumeration and API-backed resources require one.

### Resource types

| Type | Description |
| :--- | :--- |
| `repos` | Git repository history (default) |
| `forks` | Include forked projects |
| `mrs` | Merge request descriptions |
| `mr-comments` | Comments on merge requests (auto-included with `mrs`) |
| `issues` | Issue descriptions |
| `issue-comments` | Comments on issues (auto-included with `issues`) |
| `snippets` | Project snippet contents |
| `releases` | Release descriptions |
| `release-assets` | Downloadable release assets and source archives (auto-included with `releases`) |
| `ci-jobs` | CI job logs |
| `ci-artifacts` | CI job artifacts (auto-included with `ci-jobs`) |

### Target selection

```sh
# scan a project's git history
betterleaks gitlab https://gitlab.com/my-company/backend

# scan all projects under a group, including subgroups by default
betterleaks gitlab https://gitlab.com/my-company

# scan a group without recursing into subgroups
betterleaks gitlab \
	--include-subgroups=false \
	https://gitlab.com/my-company

# enumerate every group visible to the token
betterleaks gitlab \
	--all-groups \
	https://gitlab.com/

# exclude forks and project globs
betterleaks gitlab \
	--include=forks \
	--exclude-repo 'my-company/*-archive' \
	--exclude-repo 'my-company/playground-*' \
	https://gitlab.com/my-company

# skip repo git history, scan only API resources
betterleaks gitlab \
	--include=issues,mrs,issue-comments,mr-comments \
	--exclude=repos \
	https://gitlab.com/my-company
```

### Issues, MRs, comments

```sh
betterleaks gitlab \
	--include=issues,mrs,issue-comments,mr-comments \
	--since 2026-01-01 \
	https://gitlab.com/my-company/backend

betterleaks gitlab \
	--include=issues,mrs,issue-comments \
	--since 2026-01-01 \
	--until 2026-04-01 \
	https://gitlab.com/my-company
```

### Releases, snippets, CI

```sh
# snippets
betterleaks gitlab \
	--include=snippets \
	https://gitlab.com/my-company/backend

# releases and release assets
betterleaks gitlab \
	--include=releases \
	https://gitlab.com/my-company/backend

# releases, but skip downloadable assets
betterleaks gitlab \
	--include=releases \
	--exclude=release-assets \
	https://gitlab.com/my-company/backend

# CI job logs
betterleaks gitlab \
	--include=ci-jobs \
	https://gitlab.com/my-company/backend

# CI job logs and artifacts
betterleaks gitlab \
	--include=ci-jobs,ci-artifacts \
	https://gitlab.com/my-company/backend
```

### Single GitLab resource

```sh
# merge request
betterleaks gitlab https://gitlab.com/my-company/backend/-/merge_requests/1234

# issue
betterleaks gitlab https://gitlab.com/my-company/backend/-/issues/99

# snippet
betterleaks gitlab https://gitlab.com/my-company/backend/-/snippets/55

# release tag
betterleaks gitlab https://gitlab.com/my-company/backend/-/releases/v1.2.3

# pipeline
betterleaks gitlab https://gitlab.com/my-company/backend/-/pipelines/123456789

# job
betterleaks gitlab https://gitlab.com/my-company/backend/-/jobs/987654321
```

### Self-managed GitLab

```sh
betterleaks gitlab \
	--base-url=https://gitlab.example.com/ \
	https://gitlab.example.com/platform-team/backend
```

---

## `huggingface`

`huggingface` takes a Hugging Face owner, repository, or Storage Bucket URL. The alias `hf` is equivalent. Owner and repo targets scan model, dataset, and Space git history by default. Use `--include` to add community resources or buckets, and `--exclude` to skip resource types.

Set `HUGGINGFACE_TOKEN` or `HF_TOKEN` in the environment before scanning private resources, owner resources that require auth, community content, or Storage Buckets. You can also pass `--token`.

### Resource types

| Type | Description |
| :--- | :--- |
| `repos` | Model, dataset, and Space git repository history (default for owner/repo targets) |
| `discussions` | Hugging Face discussion comments |
| `prs` | Hugging Face pull request comments |
| `buckets` | Hugging Face Storage Bucket object contents (default for bucket targets) |

### Target selection

```sh
# scan all models, datasets, and Spaces for an owner
betterleaks hf https://huggingface.co/my-company

# scan a model repository
betterleaks hf https://huggingface.co/my-company/model-name

# scan a dataset repository
betterleaks hf https://huggingface.co/datasets/my-company/dataset-name

# scan a Space repository
betterleaks hf https://huggingface.co/spaces/my-company/space-name

# include discussions and PR comments
betterleaks hf \
	--include=discussions,prs \
	https://huggingface.co/my-company/model-name

# skip repo git history, scan only community content
betterleaks hf \
	--include=discussions,prs \
	--exclude=repos \
	https://huggingface.co/my-company/model-name

# exclude repos or buckets by owner/name glob
betterleaks hf \
	--exclude-repo 'my-company/test-*' \
	https://huggingface.co/my-company
```

### Storage Buckets

Hugging Face Storage Buckets are scanned through the Hugging Face source, not the `s3` source. Bucket scans accept both Hugging Face web URLs and `hf://` bucket paths.

```sh
# scan a bucket or bucket prefix
betterleaks hf hf://buckets/my-company/logs/prod/

betterleaks hf https://huggingface.co/buckets/my-company/logs/prod/

# include buckets when scanning an owner
betterleaks hf \
	--include=buckets \
	https://huggingface.co/my-company

# skip bucket objects above a custom size
betterleaks hf \
	--max-bucket-object-size=1073741824 \
	hf://buckets/my-company/logs/

# scan archives inside bucket objects
betterleaks hf \
	--max-archive-depth=2 \
	hf://buckets/my-company/artifacts/
```

Bucket objects larger than 1 GiB log a warning before download when they are not skipped by `--max-bucket-object-size`.

---

## `s3`

`s3` takes a single URL describing either one bucket or a glob of buckets to enumerate. The same command works against AWS, Cloudflare R2, MinIO, Backblaze B2, DigitalOcean Spaces, Wasabi — anything speaking the S3 REST API.

### Choosing a URL form

Two URL schemes are supported and the docs below default to `https://`:

- **`https://`** is explicit about the endpoint (host + region). Required for any non-AWS provider — R2, MinIO, B2, DigitalOcean Spaces, Wasabi. Use this in CI and scripts; the region is pinned so there's no extra round-trip and no failure mode if AWS's global endpoint is unreachable.
- **`s3://`** is an AWS-only shorthand. The endpoint is implied (`s3.amazonaws.com`) and the bucket's region is auto-probed via a `HEAD` request that reads the `x-amz-bucket-region` header. Convenient for one-off scans where you'd rather not look up the region. The probe fails loud if the bucket can't be reached.

If you don't know whether `s3://` or `https://` is right for you, prefer `https://`.

### URL forms

| URL | What it scans |
| :--- | :--- |
| `https://my-bucket.s3.us-west-2.amazonaws.com/prefix/` | One AWS bucket, optionally narrowed by key prefix |
| `https://s3.us-east-1.amazonaws.com/my-bucket/` | AWS path-style |
| `s3://my-bucket/prefix/` | AWS shorthand (region auto-probed) |
| `https://<bucket>.<account>.r2.cloudflarestorage.com/` | One Cloudflare R2 bucket |
| `https://<account>.r2.cloudflarestorage.com/<bucket>/` | R2 path-style |
| `http://localhost:9000/my-bucket/` | MinIO or other generic endpoint (needs `--region`) |
| `'https://s3.us-east-1.amazonaws.com/*'` | Enumerate all buckets in the AWS account |
| `'https://s3.us-east-1.amazonaws.com/prod-*/logs/'` | Enumerate buckets matching `prod-*`, scan only the `logs/` prefix in each |
| `'https://<account>.r2.cloudflarestorage.com/*'` | Enumerate all R2 buckets in the account |
| `'http://localhost:9000/*'` | Enumerate all buckets at the MinIO endpoint |

Quote any URL containing `*` so your shell doesn't expand it.

### Authentication

Credentials are resolved in this order: `--anonymous` flag → `--access-key`/`--secret-key`/`--session-token` flags → `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` env vars. With none of the three, the scan fails loud — there is no implicit fall-through to `~/.aws/credentials`.

```sh
# AWS via environment
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
betterleaks s3 https://my-bucket.s3.us-east-1.amazonaws.com/

# AWS via flags
betterleaks s3 \
	--access-key=AKIA... \
	--secret-key=... \
	https://my-bucket.s3.us-east-1.amazonaws.com/

# Public bucket, no signing (requires anonymous s3:ListBucket, not just s3:GetObject)
betterleaks s3 --anonymous https://<public-bucket>.s3.<region>.amazonaws.com/

# Cloudflare R2 (Access Key ID + Secret from the R2 dashboard)
export AWS_ACCESS_KEY_ID=<r2-access-key-id>
export AWS_SECRET_ACCESS_KEY=<r2-secret-access-key>
betterleaks s3 https://my-bucket.acct123.r2.cloudflarestorage.com/

# MinIO / generic S3-compatible
betterleaks s3 \
	--access-key=minioadmin \
	--secret-key=minioadmin \
	--region=us-east-1 \
	http://localhost:9000/my-bucket/
```

### Enumeration

Globs in the bucket position switch the source into enumeration mode: list every bucket the credentials can see, filter by the pattern, scan each match.

```sh
# every AWS bucket (requires s3:ListAllMyBuckets on the credentials)
betterleaks s3 'https://s3.us-east-1.amazonaws.com/*'

# AWS buckets matching a prefix
betterleaks s3 'https://s3.us-east-1.amazonaws.com/prod-*'

# common key prefix across many buckets
betterleaks s3 'https://s3.us-east-1.amazonaws.com/prod-*/logs/'

# every R2 bucket in an account (requires an admin-scoped R2 API token)
betterleaks s3 'https://acct123.r2.cloudflarestorage.com/*'
```

Anonymous enumeration is not possible — `ListBuckets` is account-scoped and requires authenticated credentials. Bucket-scoped tokens fail loudly on the initial `ListBuckets` call; switch to a single-bucket URL or upgrade the token's scope.

Per-bucket failures during enumeration (region probe errors, `AccessDenied`, etc.) are logged and non-fatal — the scan continues to the next bucket.

### Object filters and limits

```sh
# raise the per-object size cap (default: 250 MiB)
betterleaks s3 --max-object-size=1073741824 https://my-bucket.s3.us-east-1.amazonaws.com/

# scan inside archives (.zip, .tar.gz, ...) in S3 objects
betterleaks s3 --max-archive-depth=2 https://my-bucket.s3.us-east-1.amazonaws.com/

# fewer concurrent GETs against rate-limited endpoints (default: 16)
betterleaks s3 --workers=4 https://my-bucket.s3.us-east-1.amazonaws.com/
```

Objects in `GLACIER`, `GLACIER_IR`, and `DEEP_ARCHIVE` storage classes are skipped before fetching, as are empty objects and directory markers (`key/`).

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
