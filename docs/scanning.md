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
| Container images, historical layers, and metadata | `betterleaks container <image>` or `betterleaks container --archive image.tar` ([examples](#container)) |
| A known credential and rule | `betterleaks validate --rule-id <rule-id>` |
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

Merge commits are scanned against their first parent by default, while history
traversal still includes all parents. This catches secrets introduced during a
merge or conflict resolution, including secrets later deleted. A secret can be
reported again when merged into another branch.

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

## `validate`

Use `validate` when you already know the credential and the rule that owns it.
The command evaluates that rule's `validate` expression directly; it does not
run the rule's regex, filters, or source scanning. This is useful when the
original source is unavailable or a standalone credential no longer has the
provider context its detection regex expects.

List the rules in the selected config that support direct validation:

```sh
betterleaks validate --list
betterleaks validate --list --report-format jsonl
```

The list includes required components and named captures. Supply every listed
capture with `--capture name=value`; validation stops with an input error when
one is missing rather than reporting the credential as invalid.

Pass a credential on stdin when possible so it is not stored in shell history
or exposed in the process argument list:

```sh
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks validate --rule-id github-pat
```

A positional credential is also accepted for interactive use:

```sh
betterleaks validate --rule-id github-pat 'ghp_...'
```

When there is no positional credential, `validate` reads piped or redirected
stdin automatically. The input is always the primary secret and is never
decoded as a command envelope. This means a JSON credential, such as a GCP
service account or application-default credential, is passed to its validator
unchanged.

Multipart credentials must supply each component explicitly with the repeatable
`--component rule-id=secret` option:

```sh
printf '%s\n' "$AWS_ACCESS_KEY_ID" |
	betterleaks validate \
	--rule-id aws-access-token \
	--component "aws-secret-access-key=$AWS_SECRET_ACCESS_KEY"
```

Every non-optional component declared by the rule is required; components
declared with `optional = true` may be omitted. Repeat `--component` when a rule
needs more than one component. Use `--capture name=value` when a validation
expression needs a named regex capture that cannot be reconstructed from the
credential. A component capture uses `--capture rule-id:name=value`.
Supplied capture values are treated as sensitive and redacted from validation
reasons and metadata just like primary and component secrets.

The default output is concise text. Use `--simple` when only the uppercase
status is needed:

```sh
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks validate --rule-id github-pat --simple
# VALID
```

`--simple` can be combined with `--no-color` for machine-readable output and
cannot be combined with JSONL.

JSONL output uses a versioned credential-report shape. Each invocation emits
one compact object followed by a newline. Finding attributes are top-level,
while validation has its own namespace so a future `analysis` object can be
added alongside it:

```json
{
  "schema_version": 1,
  "rule_id": "github-pat",
  "attributes": {
    "path": "betterleaks://validate"
  },
  "validation": {
    "status": "valid",
    "metadata": {
      "username": "octocat"
    }
  }
}
```

Multipart JSONL records use the same component terminology as rule
configuration and identify optional components explicitly:

```json
{
  "schema_version": 1,
  "rule_id": "example-credential",
  "validation": {
    "status": "valid",
    "component_sets": [
      {
        "status": "valid",
        "components": [
          {"rule_id": "account-id"},
          {"rule_id": "region", "optional": true}
        ]
      }
    ]
  }
}
```

```sh
# JSONL on stdout
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks validate \
	--rule-id github-pat \
	--report-format jsonl
```

`validate` always writes results to stdout and does not support `--report-path`
or `--report-template`. Output never includes the supplied primary, component,
or capture values. If a validator returns one in its reason or metadata, the
matching value is replaced with `[redacted]`. Attributes are sanitized the same
way. Validation metadata may still contain sensitive identity or account
information.

`--validation-debug` is not supported by `validate` because raw debug request
and response bodies can contain transformed credentials or newly issued
tokens.

`validate` honors the remaining outbound request controls from scan-time validation:
`--validation-timeout`, `--validation-max-requests`, `--validation-rps`,
`--validation-rps-rule`, `--validation-env-vars`, and
`--validation-extract-empty`. A completed validation—including `invalid`,
`revoked`, `unknown`, or `error`—is a successful command result represented by
the reported status; input, configuration, I/O, and cancellation failures
return command errors.

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
betterleaks git . --isolate-rule github-pat --isolate-rule aws-access-key

# disable selected rules
betterleaks git . --disable-rule generic-api-key

# use a baseline
betterleaks git . --baseline-path findings.json

# enable live validation
betterleaks dir . --validation --validation-status valid,unknown

# cap and rate-limit outbound validation requests
betterleaks dir . --validation \
	--validation-max-requests 1000 \
	--validation-rps 10 \
	--validation-rps-rule github-pat=2

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

---

## `container`

Scan Docker and OCI images without running them. `docker` is an alias for
`container`. Use this command for both registry references and saved image archives.

### Registry images and authentication

```sh
# Public image; ignore saved credentials and credential helpers
betterleaks container ubuntu:24.04 --anonymous

# Private image; use credentials from docker login
docker login ghcr.io
betterleaks container ghcr.io/example/app:latest

# Select a platform instead of scanning every platform
betterleaks container ubuntu:24.04 --platform linux/arm64

# Multiple images; platform selections are also repeatable
betterleaks container example/api:v1 example/worker:v1 \
  --platform linux/amd64 --platform linux/arm64
```

Bare image references always select a registry. Registry scans do not require a
running Docker daemon. Public images can be scanned without credentials; private
images use Docker's standard credential configuration, including `DOCKER_CONFIG`
and credential helpers. `--anonymous` disables credential lookup. Use
`--plain-http` only for registries served over HTTP; it does not disable HTTPS
certificate verification. Tags and digest-pinned references are supported.

### Local images and saved archives

```sh
# Image in the local Docker daemon, using the Docker CLI's configured context
betterleaks container --daemon docker wasilibs-build:latest

# Image in the local Podman image store
betterleaks container --daemon podman wasilibs-build:latest

# Docker save archive
docker image save wasilibs-build:latest -o image.tar
betterleaks container --archive image.tar

# Compressed Docker/OCI archives and OCI layout directories
betterleaks container --archive image.tar.gz --archive second-image.tar.zst
betterleaks container --oci-layout ./image-layout
```

`--daemon` requires an explicit `docker` or `podman` value and the corresponding
CLI with access to its image store. It exports the local image with
`docker image save` or `podman image save`; it does not pull a missing image.
Omitting `--daemon` selects registry scanning for image references. Archive and
layout inputs need neither a container runtime nor registry credentials. Every
image in an archive is scanned. Use `docker save` or `podman save` to retain
layers and build metadata; `docker export` and `podman export` omit image history.

Remote layers are streamed. Outer image archives and daemon exports are unpacked
into a private temporary directory, removed on completion or failure. Nested
archives may also use temporary storage. Original images and input archives are
left in place.

### Coverage and reports

By default, scans traverse all platforms and historical layers, including file
versions that later layers deleted or replaced. They also scan image config
(including environment variables and labels), build history, manifest/index
metadata, tar metadata, and artifact payloads reached through the image index.
Platform filters accept `os/architecture[/variant]`; attestations marked
`unknown/unknown` remain in scope.

Findings carry container attributes for the image, platform, layer index,
available digests, and whether a historical path is visible, overwritten,
deleted, or unknown. Common detection, validation, redaction, and
output flags apply:

```sh
# Redacted JSON report
betterleaks container example/app:latest --redact --report-path image.json --report-format json

# Validate detected credentials and write JSON
betterleaks container example/app:latest --validation --report-path validated.json --report-format json

# Show resolution, platform selection, and periodic layer progress
betterleaks container example/app:latest --log-level=debug
```

Verbose findings stream as the detector emits them, including with `--redact`.
Live redaction masks the secrets identified in each finding. Report files are
written when the scan finishes and also mask detected secrets repeated in other
findings' labels and context.

Debug progress reports stored layer bytes read, usually compressed. The final
scanned-byte total measures detector input after exclusions and archive
expansion; these numbers need not match. Default prefilters still exclude paths
such as Python libraries and `node_modules`. To include those paths, export a
standalone configuration and replace its top-level `prefilter` expression with
`false`:

```sh
betterleaks config show > exhaustive.toml
# Edit the top-level prefilter in exhaustive.toml to: prefilter = 'false'
betterleaks container example/app:latest --config exhaustive.toml
```

Extending the default configuration adds prefilters; it cannot remove the
inherited exclusions. Detection rules and finding filters still apply.

Filesystem layers support uncompressed tar, gzip, and zstd. Outer Docker/OCI
archives also support bzip2 and xz compression. Nested archives use the normal
file source's format detection. Missing blobs, unsupported encryption, and
legacy Docker schema-1 manifests produce incomplete scans.

An image scan does not inspect running containers' writable layers, mounted
volumes, runtime-injected environment variables, or build stages absent from the
image. Registry enumeration and OCI referrers discovery are outside its scope.

### Container provenance

`Attributes.path` (also available as `File` in v1 reports) is the absolute container path, with `!` separating nested
archive members, for example `/app/bundle.zip!.env`. Metadata uses virtual paths
such as `@config`, `@history/0`, `@manifest`, and `@index`. Escaped JSON strings
also receive a decoded representation with a `#decoded` suffix; coordinates
refer to the indicated representation.

Findings also carry declared image authors, source repository, and revision
when available. Config labels take precedence over manifest annotations;
legacy maintainer/author values provide a fallback for authors. These are
image-supplied declarations, not verified authorship. Oversized attribution
values are scanned as metadata but omitted from repeated finding attributes.

Findings indicate whether a file occurrence is `visible`, `overwritten`,
`deleted`, or `unknown`, and identify the layer that first hid it when available.

Layers are read from newest to oldest, but provenance identifies the earliest
subsequent change to each historical occurrence. If layer 0 creates `/token`,
layer 1 deletes it, and layer 2 creates it again, the layer-0 finding is `deleted`
by layer 1. Recreating the pathname does not rewrite that history. Within one
layer, whiteouts remove older occurrences before additions; they never hide a
file introduced in that same layer.

Path state describes an occurrence at its original path, not whether the secret
is absent from the final image. Copies and hardlinks may retain the value.
Links are scanned as metadata and are never followed into the host filesystem.
An unreadable upper layer makes lower-layer path states `unknown`; Windows
images also use `unknown` because their filesystem visibility is not modeled.

Docker save archives do not preserve the original registry manifest digest or
necessarily the original compressed layer bytes. Those unavailable digests are
omitted. Config digests, diff IDs, tags, and layer indexes still identify findings.

### Limits and incomplete scans

| Flag | Default | Behavior |
| :--- | :--- | :--- |
| `--max-file-size` | Unlimited | Caps individual layer files and stored artifact blobs; sparse files use their expanded size |
| `--max-archive-depth` | `8` | Bounds nesting within layer files; the outer image archive and filesystem layer do not consume this budget |
| `--max-archive-size` | `20 GiB` | Caps the full expanded outer tar stream, including headers, padding and trailing data, and extracted file bytes; applies to daemon exports; `0` selects this default |

Sizes accept units such as `250MiB` or `30GiB`. The shared v1 flag
`--max-target-megabytes` also sets the file limit unless `--max-file-size` is
explicitly supplied. These are not aggregate limits on expansion inside nested
archives.

Additional bounds apply per image: at most one million layer entries and 64 MiB
of normalized entry-path text across all its layers, including filtered entries.
These bound the names retained for duplicate detection and historical path
tracking. After a layer's tar end marker, at most 16 MiB of zero padding is
accepted while validating the compression trailer and digest. Nonzero trailing
data is an error. This padding bound does not cap normal layer file contents.
JSON metadata input and each decoded representation are limited to 16 MiB;
image-index nesting is limited to 32, outer archives to one million entries,
and zstd decoder memory to 256 MiB. Limit failures mark the scan incomplete.

Container scans use strict archive verification: missing or corrupt blobs,
unreadable nested archives, checksum failures, and exceeded limits log a partial
scan and exit with code `1`, overriding `--exit-code`. The v1 report formats do
not include a scan-state field; check the process exit status and diagnostics.
Findings already collected are preserved, and independent content continues
where possible.
Configured prefilter exclusions do not count as errors. Strict verification is
automatic for containers; there is no `--strict-archives` flag.

Container fingerprints include image, platform, layer, and metadata identity, so
ignoring a finding in one historical layer does not ignore the same path in a
different layer. Existing filesystem and Git fingerprints remain unchanged.

### Container SDK

Import `github.com/betterleaks/betterleaks/sources/container` and pass the source
to a v1 detector:

```go
src := &container.Source{
    Images:          []string{"ghcr.io/example/app:latest"},
    MaxArchiveDepth: 8,
    Prefilter:       detector.SkipFunc(),
}
for result := range detector.Run(ctx, src) {
    if result.Err != nil {
        // Record incomplete coverage; independent content may still be scanned.
        continue
    }
    // Process result.Finding, including its container attributes.
}
```

The SDK archive-depth default is zero; set `MaxArchiveDepth` explicitly to scan
nested archives. `Keychain`, `Transport`, and `Logger` allow caller-supplied
registry authentication, HTTP transport, and structured diagnostics.
