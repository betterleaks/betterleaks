# Advanced Scanning Guide

Use `--help` for full flag descriptions. This page is for patterns.

## Provider modes and v1 flag migration

Scan commands validate and analyze supported credentials by default.
`--no-analysis` retains validation only. `--offline` disables both provider stages;
fetching a remote source can still use the network. `--no-validation` has been
removed in favor of `--offline`.

The v1 provider-control aliases are no longer accepted:

| Old flag | v2 flag |
| :--- | :--- |
| `--validation-workers` | `--provider-workers` |
| `--validation-debug` | `--provider-debug` |
| `--validation-timeout` | `--provider-timeout` |
| `--validation-max-requests` | `--provider-max-requests` |
| `--validation-rps` | `--provider-rps` |
| `--validation-rps-rule` | `--provider-rps-rule` |
| `--validation-env-vars` | `--provider-env-vars` |

## Parallel jobs

Use `-j` or `--jobs` to set detection concurrency. Zero uses `GOMAXPROCS`;
positive values are capped at `GOMAXPROCS`.

```sh
# use up to eight concurrent detections
betterleaks filesystem . -j 8
betterleaks github https://github.com/my-company -j 8
```

Sources choose their own bounded I/O concurrency. These are internal policies,
not configuration options:

| Source work | Concurrency |
| :--- | :--- |
| Filesystem readers | `GOMAXPROCS` |
| Git history processes | Up to `min(GOMAXPROCS, 4)`; one with explicit `--log-opts` |
| S3 and Hugging Face object reads | 4 |
| GitHub Actions runs | 4 |
| Provider repositories or buckets | One target at a time |
| URL and stdin | Serial |

Reading and detection overlap. When detection or finding output falls behind,
yielding blocks, readers stop advancing, and bounded enumeration queues stop
further read-ahead. Provider enumeration can queue one upcoming target while the
current target is scanned. Paginated listings stream into bounded work instead
of collecting every page first. S3 can request its next object-list page while
the previous page's bounded reads finish.

These limits bound concurrent work and queued content, not total process memory.
Each active reader can retain buffers and archive workspaces; individual API
responses and regex-engine memory also contribute. Independent source invocations
have independent limits.

`-j 1` serializes detection; sources can still read ahead. Credential evaluation
has a separate pool: `--provider-workers` defaults to 10, and zero selects that
default. `--offline` disables credential evaluations; `--no-analysis` retains
validation only. Source API request ceilings and provider rate limits remain
independent of these settings.

The Go API configures detection with `scan.WithWorkers(n)` and credential
evaluation with `analyze.WithWorkers(n)`. Sources have no worker setting. The
detection limit is shared across concurrent `Scan` and `ScanString` calls on the
same scanner. Unlike the CLI, an explicit SDK detection count is not capped at
`GOMAXPROCS`.

Custom sources keep `Fragments(ctx, yield)`: bound readers and queues, allow
blocking yields to stop upstream work, and honor cancellation. No scanner worker
count or shared budget is passed to sources.

## Pick a target

| Want to scan | Use |
| :--- | :--- |
| Filesystem | `betterleaks <path>` or `betterleaks filesystem <path>` |
| Git history | `betterleaks git [path-or-http-url]` |
| One HTTP(S) response or archive | `betterleaks url <url>` |
| Staged changes | `betterleaks git --staged` |
| Unstaged changes to tracked files | `betterleaks git --unstaged` |
| GitHub repos, Issues, PRs, Actions, Releases, Discussions, Gists | `betterleaks github <url>` |
| GitLab projects, Issues, MRs, Snippets, Releases, CI jobs/artifacts | `betterleaks gitlab <url>` |
| Hugging Face models, datasets, Spaces, discussions, PRs, buckets | `betterleaks huggingface <url>` or `betterleaks hf <url>` |
| S3 (and S3-compatible: R2, MinIO, etc.) | `betterleaks s3 <url>` |
| Liveness of a known credential | `betterleaks validate --rule <rule-id>` |
| Identity and permissions of a known credential | `betterleaks analyze --rule <rule-id>` |
| Revoke a known credential | `betterleaks revoke --rule <rule-id>` |
| Piped content | `betterleaks stdin` |
| An ignore-file entry | `betterleaks fingerprint` |

For filesystem scanning, `filesystem` (or `fs`) is optional before one or more
file or directory paths:
`betterleaks . --offline` and `betterleaks filesystem . --offline` are equivalent.
Command names take precedence, so use `./git` or `filesystem git` to scan a directory
named `git`. Running `betterleaks` without arguments shows help.

### Automatic source selection

Omit the command (or use `auto`) to select a source from a single path or URL:

```sh
betterleaks ./my-project
betterleaks auto ./my-project
betterleaks https://github.com/betterleaks/betterleaks
betterleaks https://gitlab.com/group/project.git
betterleaks https://huggingface.co/datasets/owner/dataset
betterleaks s3://bucket/prefix
betterleaks hf://buckets/owner/bucket
```

An existing local path always selects filesystem scanning, even inside a Git
checkout or when named `github.com/owner/repo`. Use `git` explicitly for local
history. A nonexistent scheme-less path is an error; no `https://` is inferred.
Multiple local paths are supported, but a remote scan accepts one target and
cannot be mixed with local paths.

GitHub and Hugging Face repository URLs and HTTP(S) paths ending in `.git`
select a temporary Git mirror and a history scan. Recognized provider owners,
organizations, buckets, and supported resource URLs select their existing
provider sources. GitLab project/group ambiguity and other HTTP(S) URLs use
Git smart HTTP discovery: a five-second request, at most three redirects, and
at most 64 KiB of advertisement inspection. A valid v0/v1/v2 advertisement
selects Git; an ordinary non-Git response or 404/410 selects URL content
(GitLab namespaces select the GitLab source). Authentication failures,
throttling, server errors, malformed Git responses, and timeouts stop with an
error. They do not silently scan a different source.

Explicit commands always override detection. Use `git <url>` when discovery
cannot identify a repository, or `url <url>` to scan the HTTP response itself.
Source-specific flags such as `--include`, `--token`, and `--region` require
an explicit command. Shared scan flags work before or after an implicit target.
SSH Git URLs and scheme-less remote addresses are not supported by this shorthand.
Self-hosted provider resources and custom S3-compatible endpoints use explicit
provider commands; arbitrary HTTP(S) Git servers can use discovery or `git`.

The SDK exposes the same classification without constructing a source:

```go
kind, err := sources.Auto(ctx, target)
if err != nil {
    return err // kind == sources.UnknownKind
}
switch kind {
case sources.FilesystemKind:
    // Construct sources.Files with Path: target.
case sources.GitKind:
    // Construct sources.Git with URL: target.
case sources.URLKind:
    // Construct sources.URL with URL: target.
    // Set MaxArchiveDepth if archives should be scanned.
}
```

Other kinds are `GitHubKind`, `GitLabKind`, `HuggingFaceKind`, and `S3Kind`.
`WithAutoHTTPClient(client)` supplies a discovery client, including custom
authentication. Detection can make network requests and respects context
cancellation. `WithAutoLogger(logger)` enables SDK diagnostics; the CLI logs the
selected source at info level and Git discovery at debug level (`--log-level debug`).
Logged URLs omit userinfo, query parameters, and fragments. The SDK does not read
credential environment variables.

---

## Finding output

Scan commands print findings in the human-readable format by default. Use
`--jsonl` to emit one versioned finding envelope per line, followed by a final scan
metadata record. The final record is also emitted when no findings are found.
Each finding record has the shape `{"schema_version":"1","finding":{...}}`.
Findings themselves do not contain `schema_version`; JSON reports version the
whole document, while JSONL versions each envelope independently.

Binary previews show readable context, replacing runs of binary bytes with
`⟨binary⟩` and underlining the secret with carets. Bytes inside the secret are
escaped rather than omitted. The original source line number appears in the
usual snippet gutter. Decoded findings
show the decoded match with carets and an `encoding` field (such as `base64` or
`percent`). Report coordinates still point to the encoded source. JSON and JSONL store the extracted secret in `match.value`;
terminal escaping does not change that value. JSON preserves text and control
characters, but invalid UTF-8 bytes are replaced with U+FFFD by the JSON encoder.

Decoded findings include top-level `encodings` and `decode_depth` fields:

```json
{
  "encodings": ["percent", "base64"],
  "decode_depth": 3
}
```

`encodings` lists distinct encodings encountered, not their decoding order.
`decode_depth` counts decoding passes, so an encoding used repeatedly appears
only once in the list. Both fields are omitted when no decoding occurred.
Component findings carry their own decoding metadata independently of the primary
finding. These fields replace the generated `decoded:*` and `decode-depth:*` tags;
`tags` contains rule-defined labels. Encoding metadata describes how the match was
decoded, not the source file's MIME type or character set.

Scanner findings and their components include `rule_hash`, identifying each
rule's definition and component dependencies, including provider expressions.
Global filters are excluded. The hash is preserved through analysis and
redaction but is not printed in pretty output. Externally constructed SDK
findings may omit it.

Primary and component matches include `match.fingerprint`, a SHA-256 hash
of the exact original `match.value` bytes, encoded as 64 lowercase hexadecimal
characters without a prefix, in `.betterleaksignore` format. The value can be a
secret or a non-secret component, such as an account ID. The fingerprint does
not include the rule, location, full regex match, captures, or other components.
Decoded values are hashed after decoding. Redaction and analysis preserve the
fingerprint; it is not recomputed from the redacted value. The field is omitted
for empty values (such as path-only findings), and externally constructed SDK
matches may omit it. Pretty output does not display fingerprints.

CLI JSON reports contain `schema_version`, `findings`, and `scan`:

```json
{
  "schema_version": "1",
  "findings": [],
  "scan": {
    "state": "complete",
    "source": {"type": "filesystem", "targets": ["./src", "./tests"]},
    "started": "2026-09-23T17:00:00Z",
    "finished": "2026-09-23T17:00:01Z",
    "betterleaks_version": "v2.0.0-rc.1",
    "config_hash": "...",
    "bytes_scanned": 1234,
    "num_findings": 0,
    "confidence_counts": {"high": 0, "medium": 0, "low": 0, "none": 0, "other": 0},
    "severity_counts": {"high": 0, "medium": 0, "unknown": 0, "none": 0},
    "status_counts": {"valid": 0, "invalid": 0, "revoked": 0, "needs_validation": 0, "unknown": 0, "error": 0, "none": 0}
  }
}
```

`state` is `complete` when scanning finishes normally, even when findings or
recoverable warnings (such as corrupt archives or permission-denied skips) are
reported. It is `incomplete` when cancellation or a fatal scan error prevents
normal completion, including failures before any findings are emitted.

`num_findings` counts reported top-level findings after all filters, including
`--status`. It equals the length of `findings` in JSON, or the number of finding
records in JSONL. Components and component sets are not counted separately.
Each of `confidence_counts`, `severity_counts`, and `status_counts` sums to
`num_findings`, and all buckets are included even when zero. `none` means the
field is unset; `unknown` is an explicit analysis or validation result. Custom
confidence values count as `other`. Incomplete scans count findings emitted so
far. A provider validation result of `error` does not itself make a scan incomplete.

`started` and `finished` are UTC timestamps for invocation start and report
finalization. `bytes_scanned` totals inspected fragment bytes across all targets,
after exclusions and source archive expansion; it is not the input's disk size.
`config_hash` identifies the resolved config after `--isolate-rule`
and `--disable-rule`. All targets use the same configuration, loaded once per
invocation. `.betterleaks.toml` files in targets or the current directory are
not loaded automatically; select a config explicitly with `--config` or the
configuration environment variables. The hash is logged at info level before
each target scan. It includes detection configuration and provider expressions
but excludes runtime settings; see
[SDK cache hashes](config.md#configuration-hashes-for-sdk-caches).

`source` records the resolved source `type` and selected `targets`. Types are
`filesystem`, `git`, `url`, `github`, `gitlab`, `huggingface`, `s3`, and `stdin`;
auto-detection reports the selected type. Stdin omits `targets`. Filesystem
targets reflect removal of nested paths and default to `["."]` when no path
is supplied. Local paths retain their spelling. Remote URLs omit credentials,
query strings, and fragments. On incomplete scans the list can include targets
that were not reached. It identifies the inputs, without recording source settings
such as Git revisions or symlink handling.

Findings are streamed immediately; `scan` is appended during finalization, so
metadata does not require retaining findings in memory. JSONL emits the same
metadata as its last line, `{"schema_version":"1","scan":{...}}`. Consumers should
distinguish this record from findings by the `scan` field. `finished` is recorded
for both states; it does not by itself indicate successful completion. On errors
or cancellation, the byte count reflects work completed so far and already
emitted findings remain in the report. Raw command
arguments are not included.

JSON Schema definitions are available for [one finding](schemas/finding.schema.json)
and [a JSON scan report](schemas/findings.schema.json), using
[Draft 2020-12](https://json-schema.org/draft/2020-12). For CLI JSONL, validate each
record against `findings.schema.json#/$defs/jsonlRecord`. Keep both schema files
together so relative references resolve. Low-level SDK `report.WriteJSON` and
`report.WriteJSONL` emit an unversioned finding array or versioned finding
envelopes, respectively; neither emits scan metadata. The CLI adds invocation metadata. These schemas
describe scan output; `validate` and `analyze` share a separate credential report. Fixed objects
reject unknown fields; source attributes and provider metadata are extensible.
Unclassified confidence is an empty string. `tags` is omitted when empty.

`-o, --output <path>` writes a second, streaming report. The filename selects the
format: `.json` writes a JSON scan report and `.jsonl` writes JSON Lines. Use
`--output -` to write the report to stdout; it writes JSON by default and JSONL
when combined with `--jsonl`. A stdout report replaces the normal finding
output so the two formats are never interleaved. If a scan is interrupted, the
report is finalized with the findings emitted before cancellation, including
the closing delimiters required for valid JSON. Abrupt termination may prevent
finalization; JSONL findings already written remain independently readable.

`--silent` suppresses terminal findings and the banner. An explicit report is
still written. Use `--no-banner` when only the banner should be hidden.

---

## Allow comments

Add `betterleaks:allow` or `gitleaks:allow` to a finding's line to suppress it.
Use `--no-allow-comments` to report these findings anyway.

---

## Ignore exact secret values

`.betterleaksignore` suppresses a secret everywhere it appears, independent of
rule, path, source, location, commit, or decoding. Each entry is the complete
SHA-256 digest of the exact secret bytes as 64 hexadecimal characters, without
a prefix:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Ignore fingerprints apply to primary and component `match.value` bytes before
validation or analysis. Ignoring a primary suppresses every finding with that
primary. Ignoring a component suppresses its standalone finding and excludes
that component match from assembly. For a required component, other combinations
remain eligible:

```text
Ignore: sha256 of ACCOUNT_B
TOKEN_A + ACCOUNT_B -> suppressed
TOKEN_A + ACCOUNT_C -> retained
```

If a required component has no remaining matches, the primary finding is
suppressed. Ignored optional components are treated as absent: the primary
survives without them, and non-ignored optional alternatives remain attached.
Only matches within the component's configured proximity participate. Captures
are not independently checked against ignore hashes.

Ignored component matches are excluded before the combination limit is applied,
so they do not consume the slots available to non-ignored combinations.

Ignore files do not modify the configured filter. Projects can also write an
explicit global filter for exact values:

```toml
filter = '''
crypto.sha256(finding["secret"]) in [
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
]
'''
```

Both forms hash exact `match.value` bytes and exclude matching components before
assembly. A filtered or ignored optional component is treated as absent.

SDK callers can pass hashes directly to `scan.WithIgnoredFingerprints(hashes...)`.
The public `fingerprint` package provides `Sum`, `Parse`, `Format`, and `Load`.
`Load` accepts an `io.Reader` and returns deduplicated hashes, line diagnostics,
and a read error. The scanner copies supplied hashes and performs no ignore-file
discovery; callers control which policy to load.

Blank lines and full-line `#` comments are allowed. Hex digits may be uppercase
or lowercase. Invalid entries are reported with their file and line number and
do not prevent valid entries from loading. Prefixed hashes (including `sha256:`), legacy location
fingerprints, `.gitleaksignore`, HMAC, Argon2id, and shortened hashes are not
accepted.

Generate an entry without putting the secret in an argument:

```sh
# prompts without echo when stdin is a terminal
betterleaks fingerprint

# hashes piped bytes exactly, including whitespace and a trailing newline
printf 'secret bytes' | betterleaks fingerprint
```

You can also copy fingerprints from JSON reports, including redacted reports:

```sh
# Primary secret fingerprints
jq -r '.findings[].match.fingerprint // empty' results.json

# Component value fingerprints (including non-secret values)
jq -r '.findings[].component_sets[]?.components[]?.match.fingerprint // empty' results.json
```

Select the values you intend to ignore; primary and component entries follow
the suppression rules above. Hashing a redacted `match.value` instead would
identify the replacement text, not the original value.

For external reproduction, use `printf`, not `echo`:

```sh
printf 'secret bytes' | sha256sum
printf 'secret bytes' | shasum -a 256
```

An explicit `--ignore-file PATH` applies to every target. Otherwise `filesystem` and
`git` use `<target>/.betterleaksignore` (or the parent directory for one file),
while `stdin`, GitHub, GitLab, Hugging Face, and S3 use
`./.betterleaksignore`. Git scans read only the current working-tree policy,
never a historical version. The active policy file is excluded from scanning.
A missing default is fine; a missing or unreadable explicit file is an error.

Fingerprints are identifiers, not confidential storage. Weak secrets can be
guessed offline from their SHA-256 values. Protect reviews of
`.betterleaksignore`—for example with `CODEOWNERS`—and keep each entry subject to
the same review as an ordinary allowlist exception.

---

## Filesystem scanning

Use `filesystem` (or `fs`) to scan files and directories in their current state.

Files are not skipped by MIME type. The default source `prefilter` still excludes
common image and font extensions. Binary files that pass
the configured path exclusions are scanned for matching byte sequences; this
does not extract rendered text from documents or images.

```sh
# current directory
betterleaks filesystem .

# multiple paths
betterleaks filesystem services/api infra/terraform

# triage with context
betterleaks filesystem . --match-context 3L

# follow file and directory symlinks (each directory is visited once)
betterleaks filesystem /mnt/data --follow-symlinks

# skip large files
betterleaks filesystem . --max-target-megabytes 20

# scan inside archives
betterleaks filesystem ./release-bundles --max-archive-depth 2

# JSON report
betterleaks filesystem . --output findings.json

# JSONL report
betterleaks filesystem . --output findings.jsonl
```

---

## `url`

Download and scan one HTTP(S) response, without following links in its content:

```sh
betterleaks url https://example.com/config.txt --offline
betterleaks url https://example.com/bundle.zip --max-archive-depth 2
betterleaks url https://example.com/export.txt --max-target-megabytes 20
```

The response is downloaded to a temporary file and scanned through the shared
file and archive handling. Archives are identified by content, including downloads
with no filename extension and redirects to download endpoints. The default
request timeout is five minutes.
`--max-target-megabytes` limits the downloaded response (zero is unlimited);
oversized responses are skipped before scanning, including chunked responses.
Archive recursion follows `--max-archive-depth`. Temporary downloads are removed
on completion or failure. Findings use `resource=url.content`, the URL path as
`path`, and a `url` attribute with userinfo, query parameters, and fragments
removed. URL userinfo can supply HTTP Basic authentication; SDK callers can
supply `sources.URL.HTTPClient` for other authentication or timeout policies.
Archive entries retain the URL attributes, so prefilters can combine `url`,
`resource`, and the full archive entry `path` (for example, `download!secret.txt`).

Like other sources, this command uses the explicitly selected configuration or
embedded defaults. It still fetches its source with `--offline`; that flag disables credential validation
and analysis requests.

---

## `git`

Use `git` for history and diffs. HTTP(S) targets are cloned to a temporary
mirror, scanned with the same history implementation, and removed afterward:

```sh
betterleaks git https://github.com/owner/repo --include=commit-messages
betterleaks git https://git.example.com/group/repo.git --token "$TOKEN"
```

`--token` overrides the known host's `GITHUB_TOKEN`, `GITLAB_TOKEN`, or
`HUGGINGFACE_TOKEN`/`HF_TOKEN`. Environment tokens are used only for HTTPS on
those public hosts, never arbitrary servers. The SDK uses an explicit
`sources.Git{URL: target, Token: token}`. `URL` cannot be combined with `RepoPath`
or a diff mode. Remote scans use the invocation's explicitly selected config or
embedded defaults; they do not discover config files in the downloaded repository
or local working directory. `--staged` and `--unstaged` require a
local repository. A clone does not contain another machine's local reflogs.

`--staged` and `--unstaged` are mutually exclusive. Without either flag, `git`
scans history. Both diff modes scan added lines; `--unstaged` excludes untracked
files. Use `betterleaks fs .` to scan complete files, including untracked files.
The former `--pre-commit` flag has been replaced by `--unstaged`; pre-commit
hooks should use `--staged` alone.

SDK callers select content with `Git.Mode`:

```go
history := &sources.Git{RepoPath: "."} // GitHistory is the zero-value mode.
staged := &sources.Git{RepoPath: ".", Mode: sources.GitStaged}
workingTree := &sources.Git{RepoPath: ".", Mode: sources.GitWorkingTree}
```

Staged scans read additions in the index relative to HEAD; working-tree scans
read tracked additions relative to the index and exclude untracked files.
`LogOpts` and `Include` apply only to history. Each `Fragments` call starts and
cleans up its own Git processes, so a source can be reused without recreating
commands or draining channels. Configuration must remain unchanged during a scan.

The shipped pre-commit hooks scan staged changes with `--offline --redact`,
so commits do not depend on network validation and findings are redacted.

```sh
# full repo history
betterleaks git .

# scan with up to four concurrent detections
betterleaks git . -j 4

# custom git log scope
betterleaks git . --log-opts="--all --since='90 days ago'"

# unstaged changes to tracked files
betterleaks git . --unstaged

# staged diff only
betterleaks git . --staged

# generate platform links in findings
betterleaks git . --platform github

# history scan with JSON output
betterleaks git . -j 8 --output findings.json

# also scan commit subjects and bodies
betterleaks git . --include=commit-messages

# also scan annotated tag messages
betterleaks git . --include=tag-messages

# scan both kinds of messages alongside file history
betterleaks git . --include=commit-messages,tag-messages

# also scan local reflog messages and the history retained by reflogs
betterleaks git . --include=reflogs

# include commit messages from that expanded history too
betterleaks git . --include=reflogs,commit-messages
```

Nonempty `--log-opts` uses one patch history stream so Git applies pathspecs,
diff filters, and history options together. For example,
`--log-opts="--all -- src/"` scans patches only under `src/`, including when
selected commits also change other paths. This also applies with
`--include=commit-messages` or `--include=reflogs`. Without `--log-opts`, history
can be partitioned across the bounded Git processes described above.
`-j` still controls detection concurrency in either case.

`--include=commit-messages` adds message scanning to the default patch scan.
Each selected commit's full message is scanned once, including empty commits
and merge commits with no patch. `--log-opts` selects the history for both
resources. Each history process reads patches and then commit messages.

Message findings use `resource=git.commit_message`, carry the commit SHA and
author metadata, and have line numbers relative to the message. Their source
link points to the commit, and they have no file path. Patch findings continue
to use `resource=git.patch_content`. Resource attributes can be used in the
same prefilters and finding filters as other sources.

`--include=tag-messages` scans each distinct annotated tag object reachable from
local tag refs, including nested annotations and tags targeting trees or blobs.
Lightweight tags have no message. All local tags are included independently of
`--log-opts`, which continues to select commit history. Tag scanning runs after
history scanning.

Tag findings use `resource=git.tag_message`. Their `git.sha` identifies the tag
object, `git.tag_name` is the name stored in the annotation, and `git.tag_ref`
identifies a local tag ref when one points directly to that object. Aliases of
the same annotation are scanned once. Tagger identity appears in
`git.tagger_name` and `git.tagger_email`, with the tagger timestamp in `git.date`.
Line numbers are relative to the message, and there is no file path. GitHub,
GitLab, and Gitea links point to the tag page when a direct tag ref is available.

`--include=reflogs` adds commits referenced by local reflogs to the history
selection. This can recover coverage of commits abandoned by amend, reset, or
rebase. Git traverses the combined selection once, so overlapping refs and
reflog entries do not duplicate commit scans. `--log-opts` limits and revision
exclusions apply to that combined history. Add `commit-messages` to scan the
full messages of those commits as well.

The same option scans the entry messages exposed by Git's reflog walk as
`resource=git.reflog_message`, independently of `--log-opts`. Findings carry
`git.reflog_ref`, a timestamp-based `git.reflog_selector`, and the ref updater's
identity in `git.reflog_actor_name` and `git.reflog_actor_email`. `git.date` is
the reflog entry time, and `git.sha` identifies its referenced commit. Each
entry is a separate resource, including entries for the same action in HEAD
and a branch reflog. Message line numbers start at one, and these local records
have no file path or web link. Reflog messages are scanned after history.

Reports show only the first line of `git.message` for these resources, appending
`...` when further message text is omitted. The full message remains available
for scanning and filtering.

These additional resources apply to repository history scans; they cannot be
combined with `--unstaged` or `--staged`.

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

# limit detection concurrency; object downloads remain independently bounded
betterleaks s3 -j 4 https://my-bucket.s3.us-east-1.amazonaws.com/
```

Objects in `GLACIER`, `GLACIER_IR`, and `DEEP_ARCHIVE` storage classes are skipped before fetching, as are empty objects and directory markers (`key/`).

---

## `validate` and `analyze`

Use `validate` to check a known credential's liveness. Use `analyze` to validate
it and then resolve identity and permissions. Both commands take an already
extracted credential and its rule ID, without running regexes, filters, or
source scanning. This is useful when the
original source is unavailable or a standalone credential no longer has the
provider context its detection regex expects.

`validate` evaluates only the rule's `validate` expression. `analyze` requires a
rule with an `analyze` expression and runs it after successful validation.
Both commands share credential inputs, request controls, and text and JSONL
report formats. `--simple` prints only the validation status.

List the rules in the selected config that support each command:

```sh
betterleaks config show ids
betterleaks config show ids --validation
betterleaks config show ids --analysis
```

IDs are sorted and printed one per line. Use `--config <path>` or
`config show ids <path>` to select a config. `config show` prints the resolved
rules, including their components and provider expressions.

Supply required captures with `--capture name=value`; the command stops with an input error when
one is missing rather than reporting the credential as invalid. Component captures
use `--capture rule-id:name=value`. Optional captures with explicit fallbacks need
not be supplied.

Pass a credential on stdin when possible so it is not stored in shell history
or exposed in the process argument list:

```sh
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks validate --rule github-pat

printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks analyze --rule github-pat
```

A positional credential is also accepted for interactive use:

```sh
betterleaks validate --rule github-pat 'ghp_...'
```

When there is no positional credential, either command reads piped or redirected
stdin automatically. The input is always the primary secret and is never
decoded as a command envelope. This means a JSON credential, such as a GCP
service account or application-default credential, is passed to its validator
unchanged.

Multipart credentials must supply each component explicitly with the repeatable
`--component rule-id=secret` option:

```sh
printf '%s\n' "$AWS_ACCESS_KEY_ID" |
	betterleaks validate \
	--rule aws-access-token \
	--component "aws-secret-access-key=$AWS_SECRET_ACCESS_KEY"
```

Every non-optional component declared by the rule is required; components
declared with `optional = true` may be omitted. Repeat `--component` when a rule
needs more than one component. Use `--capture name=value` when a validation or analysis
expression needs a named regex capture that cannot be reconstructed from the
credential. A component capture uses `--capture rule-id:name=value`.

Expressions read the primary value as `finding.secret`, primary captures as
`finding.captures["name"]`, and companion values as `components["rule-id"].secret`
or `components["rule-id"].captures["name"]`. These are the same paths used by
scan-based validation and analysis; the CLI supplies the values without regex
matching. See [the Expr input contract](config.md#data-available-to-expr).
Supplied capture values are treated as sensitive and redacted from validation
reasons and metadata just like primary and component secrets.

The default output is concise text. Use `--simple` when only the uppercase
status is needed:

```sh
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks validate --rule github-pat --simple
# VALID
```

`--simple` can be combined with `--no-color` for machine-readable output and
cannot be combined with JSONL.

JSONL output uses a versioned credential report. Each invocation emits one
compact object followed by a newline. Both commands use the same `analysis`
field: `validate` reports liveness; `analyze` adds available identity and permission
evidence. For example, an `analyze` report can include the identity and capabilities
shown below. Direct reports omit matched values
and source locations; supplied source-independent attributes remain at the root.

```json
{
  "schema_version": "1",
  "rule_id": "github-pat",
  "analysis": {
    "status": "valid",
    "identity": {"username": "octocat"},
    "capabilities": ["read"],
    "severity": "medium"
  }
}
```

Multipart records put credential combinations at the root. Each combination
has its own `analysis` result and identifies optional components explicitly:

```json
{
  "schema_version": "1",
  "rule_id": "example-credential",
  "analysis": {"status": "valid"},
  "component_sets": [
    {
      "analysis": {"status": "valid"},
      "components": [
        {"rule_id": "account-id"},
        {"rule_id": "region", "optional": true}
      ]
    }
  ]
}
```

See the [credential report schema](schemas/credential.schema.json).

```sh
# JSONL on stdout
printf '%s\n' "$GITHUB_TOKEN" |
	betterleaks analyze \
	--rule github-pat \
	--jsonl
```

Both commands write results to stdout and do not support `--output`.
Output never includes the supplied primary, component,
or capture values. If a validator returns one in its reason or metadata, the
matching value is replaced with `[redacted]`. Attributes are sanitized the same
way. Analysis metadata may still contain sensitive identity or account
information.

Use `--provider-debug` with `validate`, `analyze`, or `revoke` to include provider
HTTP diagnostics in the pretty or JSONL report: request method and URL, headers,
request and response bodies, and response status. These appear under
`analysis.debug.validation`, `analysis.debug.analysis`, or
`analysis.debug.revocation`, depending on which stages ran. Debug output is
disabled by default, and `--simple` continues to print only the status.

Authorization, token, and cookie headers are masked. Supplied primary, component,
and capture values are redacted, including their JSON, URL, and Base64 encodings.
Debug bodies can still contain other sensitive provider data.

```sh
# Inspect the provider's explanation for an unsuccessful revocation
printf '%s\n' "$GITLAB_TOKEN" |
  betterleaks revoke --rule gitlab-pat-routable-versioned --provider-debug
```

These commands honor the remaining outbound request controls from scan-time validation:
`--provider-timeout`, `--provider-max-requests`, `--provider-rps`,
`--provider-rps-rule`, and `--provider-env-vars`. A completed validation—including `invalid`,
`revoked`, `unknown`, or `error`—is a successful command result represented by
the reported status; input, configuration, I/O, and cancellation failures
return command errors.

---

## `revoke`

`revoke` executes a rule's optional `revoke` Expr for one supplied credential.
**Revocation only happens through this command. Scans never execute `revoke`
expressions.** The command does not automatically run validation or analysis;
the expression performs any prerequisite lookups itself.

```sh
# List rules with revocation support
betterleaks config show ids --revocation

# Revoke a known Buildkite user access token
printf '%s\n' "$BUILDKITE_TOKEN" |
  betterleaks revoke --rule buildkite-user-access-token --jsonl
```

The default config supports these providers:

| Provider | Rule IDs | Workflow |
| :--- | :--- | :--- |
| Buildkite | `buildkite-user-access-token` | Delete the authenticating token. |
| GitLab | `gitlab-pat`, `gitlab-pat-routable`, `gitlab-pat-routable-versioned` | Revoke the authenticating PAT through the `self` endpoint. |
| GitHub | `github-pat`, `github-fine-grained-pat`, `github-oauth`, `github-refresh-token` | Submit the token to the public credential revocation endpoint. |
| Hugging Face | `huggingface-access-token`, `huggingface-organization-api-token` | Submit the token for global invalidation. |
| Slack | `slack-user-token`, `slack-bot-token` | Revoke the token and check both `ok` and `revoked` in the response. |
| Twitch | `twitch-api-token` | Look up the token's client ID, then revoke it. A failed lookup stops the workflow. |

GitHub's `202 Accepted` response produces `unknown`, with
`analysis.status_metadata.submitted: true` and a reason explaining that completion
is unconfirmed. Its [API documentation](https://docs.github.com/en/rest/credentials/revoke)
only promises acceptance. Hugging Face also returns `202`, but
[documents immediate invalidation of matching tokens](https://huggingface.co/docs/hub/security-tokens#revoking-a-leaked-token);
its result is `revoked`, with a reason noting that prior token validity is not
disclosed. Neither public submission endpoint receives an Authorization header.

For a custom GitLab instance, set `GITLAB_BASE_URL` to the instance URL and allow
it with `--provider-env-vars GITLAB_BASE_URL`. GitHub uses the existing
`GITHUB_BASE_URL` override with the same allowlist mechanism; the configured
server must support the credential revocation endpoint.

It shares the credential input and report options documented for
[`validate` and `analyze`](#validate-and-analyze): positional secret or stdin,
`--component`, `--capture`, `--simple`, `--jsonl`, `--provider-debug`, and provider
request controls.
`--simple --no-color` prints `REVOKED`, `UNKNOWN`, or `ERROR`. JSONL uses the same
credential schema and redaction. Completed outcomes are reported through the
status; input, configuration, I/O, and cancellation failures return command errors.

Rule authors can use multiple requests and response extraction in a single Expr.
See [explicit credential revocation](config.md#explicit-credential-revocation)
for a lookup-then-delete example and the result contract.

---

## `stdin`

Use `stdin` for generated or piped content.

```sh
# file through a pipe
cat .env | betterleaks stdin

# generated JSON
terraform output -json | betterleaks stdin

# decompressed stream
curl -sL https://example.com/blob.txt.gz | gunzip | betterleaks stdin

# JSON report to stdout
some-command | betterleaks stdin --output -
```

---

## Handy shared patterns

```sh
# use a specific config
betterleaks filesystem . --config .betterleaks.toml

# only run selected rules
betterleaks git . --isolate-rule github-pat --isolate-rule aws-access-key

# disable selected rules
betterleaks git . --disable-rule generic-api-key

# retain only selected validation results
betterleaks filesystem . --status valid,unknown

# validate without credential analysis
betterleaks filesystem . --no-analysis --status valid

# disable all validation and analysis provider requests
betterleaks filesystem . --offline

# cap and rate-limit outbound provider requests
betterleaks filesystem . \
	--provider-max-requests 1000 \
	--provider-rps 10 \
	--provider-rps-rule github-pat=2

# redact output
betterleaks git . --redact

# show clipped context
betterleaks filesystem . --match-context 5L,40C

# scan archives and decoded content together
betterleaks filesystem ./artifacts --max-archive-depth 2 --max-decode-depth 5
```

---

## Related docs

- [docs/config.md](config.md)

All v2 finding and credential JSON uses snake_case. Report envelopes and
credential reports use `schema_version: "1"`; nested and standalone findings
carry no version field.
The schema version is independent of the Betterleaks application version and
changes when the report contract introduces a breaking change.
Credential state uses `analysis.status`, `status_reason`, and `status_metadata`;
permission enrichment uses `reason`, `metadata`, identity and capabilities.
`component_sets_truncated` means the 100-combination discovery limit omitted
possible credentials. Such a search cannot establish invalidity unless every
possible combination was actually tested; a tested successful combination can
still establish validity.
