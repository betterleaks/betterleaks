# Advanced Scanning Guide

Use `--help` for full flag descriptions. This page is for patterns.

## Provider modes and v1 flag migration

Scan commands detect secrets without credential validation or analysis by default.
`-v` / `--validate` enables credential validation. `-a` / `--analyze` enables
identity and permissions analysis and implies validation.
Fetching a remote source can still use the network in any mode.
`--status` requires validation or analysis to be enabled; it does not enable
either stage.
`--offline`, `--no-analysis`, and `--no-validation` are no longer accepted.
Use `-V` / `--version` to print the version; lowercase `-v` enables validation.

`BETTERLEAKS_VALIDATE` and `BETTERLEAKS_ANALYZE` accept `true` or `false` and
default to `false` when unset. Precedence is explicit flag, then the corresponding
environment variable, then the default. Analysis implies validation after these
values are resolved, so disabling validation alone does not disable analysis.
These variables apply to scan commands; the explicit `validate`, `analyze`, and
`revoke` commands keep their own behavior.

```sh
BETTERLEAKS_VALIDATE=true betterleaks fs .
BETTERLEAKS_ANALYZE=true betterleaks fs .
# Override both environment settings for this scan
betterleaks fs . --analyze=false --validate=false
```

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

Use `-j` or `--jobs` to set detection concurrency. Zero (the default) uses
`4 * GOMAXPROCS`; positive values are used as supplied. More detection workers
also allow more fragment results to be buffered and can increase memory use.

```sh
# use up to eight concurrent detections
betterleaks filesystem . -j 8
betterleaks github https://github.com/my-company -j 8
```

Sources choose their own bounded I/O concurrency, independently of detection:

| Source work | Concurrency |
| :--- | :--- |
| Filesystem readers | `GOMAXPROCS` |
| Git history workers | Up to `min(GOMAXPROCS, 8)` |
| S3 and Hugging Face object reads | 4 |
| GitHub Actions runs | 4 |
| Provider repositories or buckets | One target at a time |
| URL and stdin | Serial |
| Container images and layers | Serial input; detection uses the normal worker pool |

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
default. Credential evaluation is disabled unless enabled by `--validate`,
`--analyze`, or their environment variables. `--validate` enables validation;
`--analyze` enables both stages.
Source API request ceilings and provider rate limits remain independent of these
settings.

The Go API configures detection with `scan.WithWorkers(n)` and credential
evaluation with `analyze.WithWorkers(n)`. Source concurrency is independent;
`gogit.Source` exposes history worker counts as `Workers`. The
detection limit is shared across concurrent `Scan` and `ScanString` calls on the
same scanner. As with the CLI, zero uses `4 * GOMAXPROCS` and explicit positive
counts are not capped at `GOMAXPROCS`.

Custom sources keep `Fragments(ctx, yield)`: bound readers and queues, allow
blocking yields to stop upstream work, and honor cancellation. No scanner worker
count or shared budget is passed to sources.

## Pick a target

| Want to scan | Use |
| :--- | :--- |
| Filesystem | `betterleaks <path>` or `betterleaks filesystem <path>` |
| Git history | `betterleaks git [path-or-http-url]` |
| One HTTP(S) response or archive | `betterleaks url <url>` |
| Staged changes | Pipe `git diff --cached` into `betterleaks stdin --git-diff` |
| Unstaged changes to tracked files | Pipe `git diff` into `betterleaks stdin --git-diff` |
| Custom history / hook ranges | Pipe selected `git log -p` output into `betterleaks stdin --git-diff` |
| GitHub repos, Issues, PRs, Actions, Releases, Discussions, Gists | `betterleaks github <url>` |
| GitLab projects, Issues, MRs, Snippets, Releases, CI jobs/artifacts | `betterleaks gitlab <url>` |
| Hugging Face models, datasets, Spaces, discussions, PRs, buckets | `betterleaks huggingface <url>` or `betterleaks hf <url>` |
| S3 (and S3-compatible: R2, MinIO, etc.) | `betterleaks s3 <url>` |
| Container images, historical layers, and metadata | `betterleaks container <image>` or `betterleaks container --archive image.tar` ([examples](#container)) |
| Liveness of a known credential | `betterleaks validate --rule <rule-id>` |
| Identity and permissions of a known credential | `betterleaks analyze --rule <rule-id>` |
| Revoke a known credential | `betterleaks revoke --rule <rule-id>` |
| Piped content | `betterleaks stdin` |
| An ignore-file entry | `betterleaks fingerprint` |

For filesystem scanning, `filesystem` (or `fs`) is optional before one or more
file or directory paths:
`betterleaks .` and `betterleaks filesystem .` are equivalent.
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
select a temporary Git clone and a history scan. Recognized provider owners,
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
Source-specific flags such as `--include`, `--token`, `--clone-ref`,
`--clone-all-refs`, `--revision`, and `--region` require an explicit command.
Shared scan flags work before or after an implicit target.
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
    // Construct gogit.Source with URL: target.
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
characters without a prefix, in `.betterleaksignore` format. With `--hmac-key` or `BETTERLEAKS_FINGERPRINT_HMAC_KEY`
(or SDK `scan.WithFingerprintKey`), it is instead `hmac-sha256:` followed by the
HMAC-SHA-256 digest. Rule and config hashes are unaffected. The value can be a
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
recoverable warnings (such as filesystem/Git archive warnings, Git content over a
size limit, or permission-denied skips) are reported. It is `incomplete` when
cancellation or a source or detection error prevents full coverage, including
failures before any findings are emitted.
Container scans treat unreadable or corrupt nested archives as coverage errors,
so those failures mark the report incomplete even if other files finish scanning.

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
`filesystem`, `git`, `url`, `github`, `gitlab`, `huggingface`, `s3`, `container`, and `stdin`;
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

## Allow signatures

Add `betterleaks:allow` or `gitleaks:allow` to a finding's line to suppress it.
These are the default allow signatures. Matching is a case-sensitive literal
substring check; Betterleaks does not parse comment syntax.

Use repeatable `--allow-signature` flags to replace the defaults:

```sh
betterleaks fs . --allow-signature betterleaks:allow --allow-signature '#nosec'
```

This honors only `betterleaks:allow` and `#nosec`. Commas are literal parts of
signatures, not list separators. A marker anywhere on the finding's line can
suppress it, including inside a string or a longer word.

Use `--no-allow-signatures` to report findings regardless of allow markers.
It cannot be combined with `--allow-signature`. Empty signatures are rejected.

In the Go SDK, `scan.WithAllowSignatures("betterleaks:allow", "#nosec")` replaces
the defaults, and `scan.WithAllowSignatures()` disables allow signatures. Omitting
the option keeps the defaults. The option copies the supplied slice; when supplied
more than once, the last option sets the list.

---

## Ignore exact secret values

`.betterleaksignore` suppresses a secret everywhere it appears, independent of
rule, path, source, location, commit, or decoding. By default, each entry is the complete
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
The public `fingerprint` package provides `Sum`, `SumWithKey`, `Parse`, `Format`,
and `Load`. `SumWithKey(value, key)` selects HMAC-SHA-256 for a non-empty key
and ordinary SHA-256 for an empty key. `Hash` is an opaque, comparable value
that retains its hash mode; `Hash.IsHMAC()` identifies keyed entries.
`Load` accepts an `io.Reader` and returns deduplicated hashes, line diagnostics,
and a read error. The scanner copies supplied hashes and performs no ignore-file
discovery; callers control which policy to load.

Blank lines and full-line `#` comments are allowed. Hex digits may be uppercase
or lowercase. Invalid entries are reported with their file and line number and
do not prevent valid entries from loading. The `hmac-sha256:` prefix selects
keyed fingerprints. The `sha256:` prefix, legacy location fingerprints,
`.gitleaksignore`, Argon2id, and shortened hashes are not accepted.

Generate an entry without putting the secret in an argument:

```sh
# prompts without echo when stdin is a terminal
betterleaks fingerprint

# hashes piped bytes exactly, including whitespace and a trailing newline
printf 'secret bytes' | betterleaks fingerprint
```

For private fingerprints, supply a stable random key through
`BETTERLEAKS_FINGERPRINT_HMAC_KEY` or `--hmac-key KEY` (the flag takes precedence).
Without either, fingerprints remain SHA-256. An explicitly empty flag, or an
empty environment variable when no flag is supplied, is an error. Keys are used
as exact bytes, without trimming or decoding.

```sh
# Prefer the environment variable in CI; flag values can appear in process arguments or logs.
printf '%s' "$SECRET" | betterleaks fingerprint --hmac-key "$KEY"
betterleaks fs . --hmac-key "$KEY" --redact=100 -o report.json
```

HMAC fingerprints use `hmac-sha256:<hex>`. Use the same private key for scans and
ignore generation; changing it requires regenerating ignore entries. Mixed
SHA-256/HMAC ignore modes are rejected. HMAC protects against guessing values
from published fingerprints without the key; ordinary SHA-256 does not.
It does not redact report contents.

The SDK remains explicit: `scan.WithFingerprintKey(key)` copies a non-empty key;
`fingerprint.SumWithKey(value, key)` generates matching ignore entries. SDK code
does not read the environment automatically. Rule/config hashes and
`crypto.sha256` expressions are unaffected.

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

An explicit `--ignore-file PATH` applies to every target. Otherwise `filesystem`
and local `git` scans use `<target>/.betterleaksignore` (or the parent directory
for one file). Git URL scans, `stdin`, GitHub, GitLab, Hugging Face, and S3 use
`./.betterleaksignore`. Local Git scans read the policy from the supplied path,
including a bare repository or a work-tree subdirectory; they do not search
parent directories for a policy. Git scans never load a historical or remotely
fetched policy file. The active policy file is excluded from scanning.
A missing default is fine; a missing or unreadable explicit file is an error.

Fingerprints are identifiers, not confidential storage. Weak secrets can be
guessed offline from their SHA-256 values. Protect reviews of
`.betterleaksignore`—for example with `CODEOWNERS`—and keep each entry subject to
the same review as an ordinary allowlist exception.

---

## Filesystem scanning

Use `filesystem` (or `fs`) to scan files and directories in their current state.
`--max-target-megabytes` applies to filesystem and URL scans; object-store
sources have their own size-limit flags.

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
betterleaks url https://example.com/config.txt
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
embedded defaults. Source fetching uses the network even when credential
validation and analysis are disabled, as they are by default.

---

## `git`

The Git source reads repository objects in-process using stable go-git v5 and
Betterleaks' own object and pack readers. It never runs
`git`, hooks, diff or textconv helpers, filters, SSH, or credential helpers, so
scanning an untrusted repository cannot execute anything it configures.

With no target, `betterleaks git` scans the repository containing the current
directory. By default it scans the history reachable from HEAD and every ref
except `refs/notes/*`, which has a separate `notes` resource. Each commit is
compared with its first parent and added lines are scanned. Merge commits are
walked through all parents but not diffed; `--include=merges` adds their
patches. Temporary ref files and directories ending in `.lock` are ignored.
To scan added lines in staged or uncommitted working-tree changes, use the
[patch workflow](#caller-supplied-patches).

By default, HTTP(S) URL scans fetch branches (`refs/heads/*`), tags (`refs/tags/*`),
and notes (`refs/notes/*`). This also applies to Git history fetched by the `github`,
`gitlab`, and `huggingface` sources. Hosting services also publish refs for pull
requests, merge requests, and other code reviews, such as `refs/pull/*`,
`refs/merge-requests/*`, `refs/changes/*`, and `refs/pr/*`. These refs are excluded
by default, so history reachable only through them is not downloaded or scanned.
Notes are scanned when `--include=notes` is selected.

```sh
betterleaks git .                                # all history
betterleaks git . --revision=origin/main..HEAD   # commits not yet on origin/main
betterleaks git . --include=commit-messages,notes
betterleaks git . --since=2026-01-01 --author='Example <'
betterleaks git https://github.com/owner/repo
```

### Git options

These options belong to the explicit `git` command. Shared detection, output,
validation, and diagnostic flags are also available; see `betterleaks git --help`.

| Option | Default | Effect |
|---|---|---|
| `[repo]` | `.` | Local repository, a path inside it, or an HTTP(S) repository URL. |
| `--token` | Known-host environment variable, if set | Authenticate an HTTPS clone; see [Remote repositories](#remote-repositories). |
| `--clone-ref` | None | Add a fully qualified ref or pattern to the URL fetch; repeatable. |
| `--clone-all-refs` | Off | Fetch all advertised refs under `refs/`; URL scans only. |
| `--revision` | HEAD and all non-note refs | Start at a revision, or select an `A..B` range, from available history. |
| `--since`, `--until` | Unbounded | Inclusive committer-date bounds, RFC3339 or `YYYY-MM-DD` (UTC). |
| `--author`, `--committer` | No filter | Go regular expressions over `Name <email>`. |
| `--max-commits` | `0` (unlimited) | Limit selected commits in the history walk. |
| `--include` | No additions | Add resource types; comma-separated or repeated. |
| `--exclude` | No exclusions | Remove resource types; comma-separated or repeated. |
| `--git-max-blob-mib` | `64` | Skip larger blobs with a warning; `0` also selects 64, maximum 4096. |
| `--max-archive-depth` | `8` | Expand nested archives up to this depth; `0` disables expansion. |
| `--allow-external-objects` | Off | Permit Git storage outside the repository's directory. |
| `--platform` | Infer from the fetch remote | Link platform: `github`, `gitlab`, `azuredevops`, `gitea`, `bitbucket`, `unknown` (auto), or `none`. |

### What to fetch

For `git` URL scans, `--clone-ref` adds a fully qualified ref or a pattern with at
most one `*` to the default branches, tags, and notes. Repeat the flag for multiple
refs, and quote patterns to keep the shell from expanding them. Names are kept
unchanged in the clone; short branch names, commit hashes, and `source:destination`
refspecs are not accepted. A missing exact ref is an error; an unmatched pattern
adds nothing. Values are not comma-separated: a comma is part of the ref name.

```sh
# Add all GitHub PR heads, including PRs from forks
betterleaks git https://github.com/owner/repo --clone-ref='refs/pull/*/head'

# Add all GitLab merge-request heads
betterleaks git https://gitlab.com/owner/repo --clone-ref='refs/merge-requests/*/head'

# Fetch every advertised ref, including review and other host-specific refs
betterleaks git https://github.com/owner/repo --clone-all-refs
```

`--clone-all-refs` includes every advertised ref under `refs/`. When both options
are supplied, `--clone-ref` values are checked for valid syntax but otherwise
ignored. Fetching all refs can download substantially more history. It does not
enumerate or clone fork repositories, but review refs in the target repository
can bring in commits from forks. Hidden refs and unreachable objects are not
requested.

Both options require a URL and always produce a temporary bare repository with
full history and no checkout. They control the download; `--revision` and
`--include`/`--exclude` control the scan afterwards. Without a revision, fetched
review history is scanned along with the repository's ordinary history. Notes
still require `--include=notes`. These options fetch Git content, not PR titles,
descriptions, or comments. To scan just one PR, see below. Local scans read the
refs already present and never fetch; clone flags are rejected for local paths.
The `github`, `gitlab`, and `huggingface` commands accept `--clone-all-refs` and
apply it to every repository they clone. `--clone-ref` needs the `git` command,
and implicit targets accept neither flag.

### What to scan

`--include` adds resources to the default and `--exclude` removes them. Both take
comma-separated or repeated values. Unknown names, a name in both lists, and a
selection that leaves nothing to scan are errors.

| Resource | Scans | Default |
|---|---|---|
| `history` | Added lines in each commit's patch | On |
| `merges` | Merge commits' patches against their first parent | Off |
| `commit-messages` | Each commit's full message | Off |
| `notes` | Every version of every note under `refs/notes/*`, including removed notes | Off |
| `tag-messages` | Annotated tag messages | Off |
| `reflogs` | The text of local reflog entries, and the commits they remember, such as ones removed by reset, amend, or rebase | Off |
| `objects` | Every stored blob, whole, once per object | Off |
| `unreachable-objects` | Stored blobs not reachable from HEAD or any ref | Off |

`merges` controls which history patches are scanned and requires `history`.
`reflogs` adds the commits it remembers to `history` and `commit-messages`,
whichever are on, and always scans the entry text. Entries record each commit's
subject line and URLs passed to `git pull`, credentials included.
Without `merges`, merge commits are still walked through all parents, and their
messages are scanned when `commit-messages` is on. A merge patch repeats the
changes its branch's commits already added; only conflict resolutions and edits
made in the merge itself are new.

`objects` and `unreachable-objects` scan whole blobs, archives included, with
`resource=git.blob` and `git.blob_sha` but no path or commit: a blob has neither.
Reflogs and the index don't make a blob reachable, so abandoned and staged
content counts as unreachable. `objects` includes the unreachable blobs.

| Goal | Flags |
|---|---|
| History with merge patches | `--include=merges` |
| Only commit messages | `--include=commit-messages --exclude=history` |
| Abandoned local history | `--include=reflogs` |
| Everything | `--include=merges,commit-messages,notes,tag-messages,reflogs,objects` |

### Which commits

- `--revision=REV` starts at one revision. `--revision=A..B` scans the commits
  reachable from B but not from A; `A..` means `A..HEAD` and `..B` means `HEAD..B`.
  `A...B` is not supported. This selects commits from available history; it does
  not fetch additional refs. Abbreviated object IDs must identify a unique
  commit or annotated tag that peels to a commit; ambiguous prefixes fail.
  A full object ID naming a blob, tree, or missing object fails even if a branch
  has the same name. Use `refs/heads/NAME` to select such a branch explicitly.
- `--since` and `--until` filter by committer time, in RFC3339 or `YYYY-MM-DD`
  (UTC). A date-only `--until` includes that whole day. Filtering never prunes the
  walk, so backdated commits are still found.
- `--author` and `--committer` are Go regular expressions matched against
  `Name <email>`.
- `--max-commits=N` stops after N commits pass the date and identity filters,
  across all history starting points. The walk prioritizes newer committer dates
  among discovered commits. Parents become available as their children are
  visited, so timestamps out of ancestry order do not produce a global date sort.
- `--include=reflogs` adds the reflogs' commits to whatever `--revision`
  selects. Commits a range excludes stay excluded.
- A path inside a work tree scans the whole repository containing it, as Git does.
- In a shallow clone, the oldest fetched commits are scanned as if they were root
  commits, as `git log -p` shows them: their whole tree appears as added. For
  exact attribution, fetch full history (`fetch-depth: 0` in GitHub Actions).

The revision, date, and identity filters combine with AND. Object scans are not
restricted by these filters or `--max-commits`. Notes and tag and reflog messages
aren't restricted by `--revision`. Date and identity filters apply to note
commits, and `--max-commits` applies separately to each notes ref. Tag and reflog
messages have none of these commit filters.

On URL scans these flags do not reduce the fetch. Branch refs are stored as
`refs/heads/main` (short name `main`), rather than `origin/main`. Use
`--revision=main..feature-branch` for a URL and your local ref names for a local scan.

### Scanning a pull request

For a PR whose source branch exists in the target repository, a URL scan can
select its commits directly. For example, to scan commits on `feature-branch`
that are not reachable from `main`:

```sh
betterleaks git https://github.com/owner/repo --revision=main..feature-branch
```

For a GitHub PR from a fork, add that specific PR ref to the URL fetch and select
its commits with `--revision`. Replace `main` with the PR's base branch and `123`
with its number:

```sh
betterleaks git https://github.com/owner/repo \
  --clone-ref=refs/pull/123/head \
  --revision=main..refs/pull/123/head

# The equivalent for a GitLab merge request
betterleaks git https://gitlab.com/owner/repo \
  --clone-ref=refs/merge-requests/123/head \
  --revision=main..refs/merge-requests/123/head
```

`--clone-ref` adds the PR's history to the download; the range scans only commits
reachable from the PR head but not from `main`. Passing only
`--revision=refs/pull/123/head` does not fetch the PR ref and fails because it is
unavailable. This also works for a GitHub PR whose source branch has been deleted,
provided its PR ref is still advertised. For a local scan, fetch the PR yourself:

```sh
git fetch origin main
git fetch origin refs/pull/123/head:refs/heads/pr-123
betterleaks git . --revision=origin/main..pr-123
```

### Finding metadata

- Patches: `path`, line numbers, `git.sha`, author, committer, and `git.blob_sha`.
- Commit messages: `resource=git.commit_message` with commit metadata. Line
  numbers are relative to the message.
- Notes: `resource=git.note`, `git.notes_ref`, and `git.note_target` (the
  annotated object). `git.sha` and author describe the note edit, not the
  annotated commit.
- Tag messages: `resource=git.tag_message`, `git.tag_sha`, `git.tag_target`,
  tagger, and `git.tag_source_ref`. Only the outermost annotation of a nested tag
  has `git.tag_ref` and a tag link.
- Reflog messages: `resource=git.reflog_message`, `git.reflog_ref`, actor,
  `git.reflog_date`, old and new IDs, and the log file and line. A reflog actor
  is who moved the ref, not who wrote the commit.

Links are built from the repository's fetch remote. `--platform` accepts
`github`, `gitlab`, `azuredevops`, `gitea` (also for Forgejo), and `bitbucket`;
set it explicitly for self-hosted services. Omit it or use `unknown` to infer
the platform from known public hosts, or use `none` to disable links.
This only controls finding metadata and links, not authentication or fetching.
Links aren't checked over the network, so an unpublished commit can produce a
link that 404s. Findings without a link show
`local only` in terminal output.

### Limits and incomplete scans

Some content is too large to scan exactly. Betterleaks either scans more than
necessary or reports what it skipped; it never drops content silently.

- A blob larger than `--git-max-blob-mib` (default 64) is skipped with a
  warning. If rename detection would have to read a blob that large, that
  commit's files aren't paired as renames: a renamed file scans as an addition,
  which can repeat findings but never misses any.
- A commit whose tree comparison exceeds 1,000,000 entries, 100,000 changed
  paths, or 16 MiB of path names is skipped with a warning.
- A diff over one million lines, or one that takes more than a minute to compute,
  is not approximated: the whole new file is scanned instead. That can repeat
  findings but never misses any.

Skipped content and damaged archives produce warnings, as in filesystem scans.
The rest of the repository is still scanned, the scan stays complete, and the
exit code depends only on findings. To scan larger blobs, raise
`--git-max-blob-mib` (up to 4096). Missing or corrupt objects and invalid refs
stop the scan and mark it incomplete. `unreachable-objects` holds up to eight
million object IDs to classify reachability; for larger repositories, use
`objects`.

Rename detection can choose different pairings when files have equal similarity
scores. This inherited go-git behavior can change which added lines are scanned
and occasionally change findings between runs.

Local SHA-1 and SHA-256 repositories work in the same binary, without build
tags. Reftable repositories and partial clones missing required objects are
not supported; these produce incomplete scans rather than fetching missing
objects. Config files are limited to 16 MiB, individual refs to 1 MiB, and
ref directory nesting to 128 levels. Alternate traversal allows at most 4,096
distinct object directories, including the primary store. Exceeding these
bounds is an error.

When memory mapping is unavailable, pack and index reads share a pool of at
most 64 open files across the repository and its alternates. Files are reopened
as needed; reopening a replaced or modified file causes an incomplete scan.

### Storage outside the repository

A `.git` file, `commondir`, or `objects/info/alternates` can point at Git storage
anywhere on disk. By default Betterleaks refuses storage outside the repository's
directory, so a crafted repository cannot make it read, and report the secrets
of, another repository on the same machine. Linked worktrees created with
`git worktree add` are allowed because their main repository registers them.
Shared refs come from the common Git directory; `refs/bisect`, `refs/rewritten`,
and `refs/worktree` come from the selected worktree. Reflog scanning includes
the journals of all registered worktrees.
When `extensions.worktreeConfig` is enabled, worktree remote and branch
settings override individual shared settings. Unspecified settings are retained,
and URL rewrite rules are applied after merging.

Repositories cloned with `--shared` or `--reference`, and submodule checkouts
scanned directly, need `--allow-external-objects`. Relative alternates are not
supported.

Symlinks inside Git storage must stay inside it, and storage files must be
regular files, even with `--allow-external-objects`. A FIFO or device stops the
scan instead of blocking it.

### Remote repositories

HTTP(S) repositories are fetched in Go into a temporary bare repository, with no
checkout or submodules, and removed after scanning. `--token` supplies HTTPS basic
authentication; for github.com, gitlab.com, and huggingface.co the token can also
come from `GITHUB_TOKEN`, `GITLAB_TOKEN`, or `HUGGINGFACE_TOKEN`/`HF_TOKEN`.
Tokens are never inferred for other hosts. URLs with credentials, queries, or
fragments are rejected, and SSH is not supported. The GitHub, GitLab, and Hugging
Face sources clone and scan repositories the same way.
HTTP(S) cloning currently supports SHA-1 repositories. Scan an existing local
clone for SHA-256 repositories.

Fetched packs are indexed as they download, without limiting pack size,
object count, or object size: plain objects of any size are streamed. Objects
stored as deltas are then rebuilt in parallel, one delta chain per worker,
keeping up to 1 GiB of chains in memory and rebuilding older links when needed.
Index metadata grows with the object count, about 52 bytes per object. Structural
limits reject delta chains longer than 4,096 links (Git writes at most 4,095), and
delta bases or results over 4 GiB (Git deltifies only objects under
`core.bigFileThreshold`, 512 MiB by default). A corrupt pack, a response missing
a requested pack, or cancellation aborts the fetch and removes its temporary
files. `--git-max-blob-mib` applies to scanning, not fetching.

### SDK

```go
history := &gogit.Source{RepoPath: "."}
pullRequest := &gogit.Source{RepoPath: ".", Revision: "origin/main..HEAD"}
remote := &gogit.Source{URL: "https://github.com/owner/repo"}
remotePR := &gogit.Source{
    URL:       "https://github.com/owner/repo",
    CloneRefs: []string{"refs/pull/123/head"},
    Revision:  "main..refs/pull/123/head",
}
```

Set exactly one of `RepoPath` or `URL`; an empty `Source` is invalid. With an
empty `Revision`, history starts at HEAD and all non-note refs.
`Include`/`Exclude` use the CLI's resource names. `CloneRefs` and `CloneAllRefs`
correspond to the URL-only clone flags. Supply `Token` explicitly for an
authenticated URL; the SDK does not infer environment tokens.

| CLI option | `gogit.Source` field | SDK behavior |
|---|---|---|
| `--max-commits` | `MaxCount` | `0` is unlimited. |
| `--since`, `--until` | `Since`, `Until` | Inclusive `*time.Time` bounds; callers parse dates and choose any end-of-day adjustment. |
| `--git-max-blob-mib` | `MaxBlobBytes` | Bytes, not MiB; `0` selects 64 MiB. |
| `--max-archive-depth` | `MaxArchiveDepth` | `0` disables expansion; set `8` to match the CLI default. |
| `--allow-external-objects` | `AllowExternalObjects` | Off by default. |
| `--platform` | `Platform` | An `scm.Platform` value; `scm.NoPlatform` disables links. |

Skipped content is logged as a warning on `Logger`, and the scan continues.
Storage outside the repository fails with `gogit.ErrExternalStore` unless
`AllowExternalObjects` is set. The SDK additionally exposes `Workers` (default
`min(GOMAXPROCS, 8)`, maximum 16) and `CacheMiB` (default 256, maximum 4096).
`DiskCacheMiB` enables a temporary-file cache of large reconstructed objects for
repositories with deep delta chains; `0` disables it and the maximum is 4096.
These three tuning fields have no CLI flags. `RemoteURL` overrides the fetch
remote used for finding links. Don't change a Source while it is scanning.

For a complete program that applies the configuration's source prefilter and
reports warnings, see [`examples/git.go`](../examples/git.go).

### Caller-supplied patches

For anything the Git source doesn't select, such as staged changes or a
pre-receive hook, produce a patch with Git and pipe it to `stdin --git-diff`.
Betterleaks parses the stream and runs nothing itself:

```sh
set -o pipefail

# Staged additions, including an initial commit
git diff --cached --no-ext-diff --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/ |
  betterleaks stdin --git-diff --redact

# Unstaged additions to tracked files
git diff --no-ext-diff --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/ |
  betterleaks stdin --git-diff

# Any history selection your Git supports
git log -p --all --since='90 days ago' --diff-merges=first-parent --format=medium --no-abbrev-commit \
  --no-ext-diff --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/ |
  betterleaks stdin --git-diff
```

Each flag matters:

- `--no-ext-diff` and `--no-textconv` keep Git from running diff helpers that
  repository configuration selects.
- `--no-color` is needed even when piping, because configuration can force color.
- The fixed prefixes keep file paths intact under settings like `diff.noprefix`.
- For `git log`, `--diff-merges=first-parent` supplies supported merge patches;
  `--format=medium --no-abbrev-commit` supplies the commit metadata the parser reads.
- `pipefail` makes a failed Git command fail the pipeline instead of looking like
  an empty, clean scan.

Removed and context lines and commit messages aren't scanned. Binary patches
don't contain file bytes and are skipped. Combined merge patches are rejected;
use `--diff-merges=first-parent` or `--diff-merges=separate`. SDK callers can use
`sources.GitDiff{Content: reader}`.

A pre-receive hook scans the commits being pushed. Git quarantines them until
the hook accepts the push, and `git log` inside the hook can read them:

```sh
#!/usr/bin/env bash
set -euo pipefail
while read -r old new ref; do
  [[ $new =~ ^0+$ ]] && continue                   # deleted ref
  if [[ $old =~ ^0+$ ]]; then
    range=("$new" --not --all)                      # new ref: commits on no existing ref
  else
    range=("$old..$new")
  fi
  git log -p --diff-merges=first-parent --format=medium --no-abbrev-commit \
    --no-ext-diff --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/ "${range[@]}"
done | betterleaks stdin --git-diff --redact
```

---

## `github`

`github` takes a target URL. Owner and repo targets scan git history by default; specific resource URLs scan the matching resource plus associated comments or assets by default. Use `--include` to add resource types and `--exclude` to skip types.

Here, `prs` and `pr-comments` select API text, not PR Git history. `forks`
controls repository enumeration, not which refs a clone fetches.
`--clone-all-refs` adds every advertised ref, including `refs/pull/*`, to each
repository's clone. To scan one PR's commits, use
[`git --clone-ref` with `--revision`](#scanning-a-pull-request).
The `github` command's `--since` and `--until` filter API items, not Git commits.

Set `GITHUB_TOKEN` in the environment before running these examples.

### Resource types

| Type | Description |
| :--- | :--- |
| `repos` | Git repository history (default) |
| `forks` | Include forked repositories |
| `prs` | Pull request titles and descriptions |
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

Here, `mrs` and `mr-comments` select API text, not merge-request Git history.
`forks` controls project enumeration, not which refs a clone fetches.
`--clone-all-refs` adds every advertised ref, including `refs/merge-requests/*`,
to each project's clone. To scan one MR's commits, use
[`git --clone-ref` with `--revision`](#scanning-a-pull-request).
The `gitlab` command's `--since` and `--until` filter API items, not Git commits.

Set `GITLAB_TOKEN` in the environment before running these examples. Public project git history can be scanned without a token, but group/user enumeration and API-backed resources require one.

### Resource types

| Type | Description |
| :--- | :--- |
| `repos` | Git repository history (default) |
| `forks` | Include forked projects |
| `mrs` | Merge request titles and descriptions |
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

`--include=prs` scans community PR comments; it does not fetch PR Git refs.
`--clone-all-refs` adds every advertised ref, including `refs/pr/*`, to each
repository's clone. To add specific refs, use the [`git` command](#what-to-fetch).

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

## `container`

Scan Docker and OCI images without running them. `docker` is an alias for
`container`. Use an explicit command; automatic source selection does not infer
container images from registry references or saved archives.

### Registry images and authentication

```sh
# Public image; ignore saved credentials
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
images use file-based credentials. The first existing file is used, in this order:
`$DOCKER_CONFIG/config.json` (or `~/.docker/config.json`), `$REGISTRY_AUTH_FILE`,
`$XDG_RUNTIME_DIR/containers/auth.json`, then
`$XDG_CONFIG_HOME/containers/auth.json` (or `~/.config/containers/auth.json`).
Basic credentials, identity tokens, registry tokens, and Docker Hub's legacy
`https://index.docker.io/v1/` key are supported. Legacy HTTP(S) registry URL keys
with API paths are matched by exact host and port, after exact credential keys.

Docker can use an external credential helper instead of keeping credentials in
the `auths` section of its `config.json`. Two JSON settings select that helper:

- `credsStore`: the default helper for registries without an override.
- `credHelpers`: a map from registry names to helpers, overriding the default.

For example, this Docker configuration selects `docker-credential-pass` for
`ghcr.io` and `docker-credential-desktop` for other registries:

```json
{
  "credsStore": "desktop",
  "credHelpers": { "ghcr.io": "pass" }
}
```

These are Docker configuration keys, not Betterleaks flags; the corresponding
helper programs must already be installed. Credential-helper execution is
disabled by default in Betterleaks. In that mode, nonempty file credentials take
precedence over helper settings; a helper-only configuration
returns an explicit error. To allow your configured helpers:

```sh
betterleaks container ghcr.io/example/private:latest --credential-helpers
```

With this opt-in, Betterleaks uses the registry-specific helper if configured,
otherwise the default helper. A selected helper takes precedence over credentials
stored directly in the file. Betterleaks executes
`docker-credential-<configured-suffix> get` directly, without a shell,
and supplies the registry on stdin. It uses `PATH` to locate the configured
helper; the flag does not accept a command or executable path. Only enable it
for helper configuration and executables you trust. Helpers have a 30-second
timeout (or the caller's earlier deadline) and a 1 MiB response limit. Helper
stdout/stderr are not included in failure diagnostics. The standard
credentials-not-found response permits anonymous registry access.

`--anonymous` bypasses all credential lookup, even when `--credential-helpers`
is also supplied. Local daemon exports, saved archives and layouts do not use
registry helpers. Library callers can set `CredentialHelpers: true` for the
same behavior, or explicitly provide a `Keychain` for other credential
providers; that caller-supplied code controls its own execution and timeouts. Use
`--plain-http` only for registries served over HTTP; it does not disable HTTPS
certificate verification. Tags and digest-pinned references are supported.

### Local images and saved archives

```sh
# Image in the local Docker daemon, using its API socket
betterleaks container --daemon docker wasilibs-build:latest

# Image in the local Podman image store
betterleaks container --daemon podman wasilibs-build:latest

# Explicit endpoint, including a rootless engine or a forwarded VM socket
betterleaks container --daemon podman \
  --daemon-host "unix://$XDG_RUNTIME_DIR/podman/podman.sock" wasilibs-build:latest

# Docker save archive
docker image save wasilibs-build:latest -o image.tar
betterleaks container --archive image.tar

# Compressed Docker/OCI archives and OCI layout directories
betterleaks container --archive image.tar.gz --archive second-image.tar.zst
betterleaks container --oci-layout ./image-layout
```

`--daemon` requires an explicit `docker` or `podman` value and access to its
running API service. Neither executable is required or invoked. Betterleaks
requests `GET /images/{name}/get`, then feeds the response into the existing
Docker/OCI archive reader. It never pulls a missing image or starts the engine.
Docker documents this [image export endpoint](https://docs.docker.com/reference/api/engine/version/v1.51/);
Podman supplies a [Docker-compatible API service](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html).

`--daemon-host` overrides saved connection profiles and environment settings,
including Docker TLS settings. Supported schemes are `unix://`, `tcp://`,
`http://`, `https://`, and local Windows `npipe:////./pipe/name` endpoints.
Explicit `tcp://` uses HTTP; explicit `https://` verifies the server with system
roots. SDK callers can supply custom TLS through `DaemonTransport`.

Docker connection selection follows this order:

1. `--daemon-host`.
2. `DOCKER_CONTEXT` (a context **name**, not a socket address).
3. `DOCKER_HOST`.
4. The saved `currentContext` in `$DOCKER_CONFIG/config.json` (default
   `~/.docker/config.json`).
5. The default local socket: `unix:///var/run/docker.sock`, or
   `npipe:////./pipe/docker_engine` on Windows.

Named Docker contexts load their engine endpoint and CA/client certificates
from Docker's context store. They do not inherit Docker TLS environment settings.
The special `default` context uses `DOCKER_HOST` and Docker TLS environment
settings. For that connection, `DOCKER_TLS_VERIFY` enables verified TLS;
`DOCKER_TLS` alone enables TLS **without server certificate verification**, as
in Docker. Both variables are enabled by any nonempty value, including `0`.
`DOCKER_CERT_PATH` selects the directory containing `ca.pem`, `cert.pem`, and
`key.pem`; otherwise the Docker configuration directory is used. Without TLS
flags, an `https://` host enables verified TLS and loads those certificates.
Setting the certificate directory alone does not enable TLS. Without a host,
enabled TLS selects `tcp://localhost:2376`. Incomplete or invalid certificate files fail the
scan instead of falling back to plaintext. Context `SkipTLSVerify` is honored.

```sh
DOCKER_CONTEXT=desktop-linux betterleaks container --daemon docker myimage:latest
DOCKER_HOST=tcp://engine.example:2376 DOCKER_TLS_VERIFY=1 \
  DOCKER_CERT_PATH="$HOME/engine-certs" betterleaks container --daemon docker myimage:latest
```

Podman uses `--daemon-host`, then `CONTAINER_CONNECTION`, then `CONTAINER_HOST`,
then the default saved connection in `podman-connections.json`. The file is read
from `$XDG_CONFIG_HOME/containers` (default `~/.config/containers`), or
`PODMAN_CONNECTIONS_CONF`. Connections defined only in `containers.conf`, and
Podman connection-specific TLS certificate files, require an explicit endpoint
(and an SDK `DaemonTransport` for custom TLS). Without a saved connection, Linux
uses `$XDG_RUNTIME_DIR/podman/podman.sock`; root without `XDG_RUNTIME_DIR` uses
`/run/podman/podman.sock`. Other platforms require a configured endpoint.

SSH profiles produce an actionable error. Betterleaks does not launch SSH or
interpret SSH proxy commands. For Podman machines, supply a Unix socket forwarded
from the VM. Podman socket activation must be configured separately.
The source does not search for engine sockets, follow HTTP redirects, use
environment HTTP proxies for the engine connection, or fall back to a CLI.
The built-in engine transport waits up to 30 seconds for response headers.
The export body has no total timeout; library callers can set a context deadline
to limit the complete scan. A custom `DaemonTransport` controls its own header
timeout.
Omitting `--daemon` selects registry scanning for image references. Archive and
layout inputs need neither a container runtime nor registry credentials. Every
image in an archive is scanned. Use `docker save` or `podman save` to retain
layers and build metadata; `docker export` and `podman export` omit image history.

Remote layers are streamed. Outer image archives and daemon exports are unpacked
into a private temporary directory, removed on completion or failure. Nested
archives may also use temporary storage. Original images and input archives are
left in place.

Docker-format archives may contain Podman's legacy `layer.tar` links. These are
resolved only to regular files within the archive, without creating filesystem
links. Escaping, missing, cyclic, or conflicting targets fail the scan; chains
are limited to 32 links and total alias-path text to 64 MiB. Other outer-archive
links are unsupported.

### Coverage and reports

By default, scans traverse all platforms and historical layers, including file
versions that later layers deleted or replaced. They also scan image config
(including environment variables and labels), build history, manifest/index
metadata, tar metadata, and artifact payloads reached through the image index.
Platform filters accept `os/architecture[/variant]`; attestations marked
`unknown/unknown` remain in scope.

Findings carry container attributes for the image, platform, layer index,
available digests, and whether a historical path is visible, overwritten,
deleted, or unknown. Common detection, validation, analysis, redaction, and
output flags apply:

```sh
# Redacted JSON report
betterleaks container example/app:latest --redact --output image.json

# Validate detected credentials and emit JSONL
betterleaks container example/app:latest --validate --jsonl

# Show resolution, platform selection, and periodic layer progress
betterleaks container example/app:latest --log-level=debug
```

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

`location.path` is the absolute container path, with `!` separating nested
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

Sizes accept units such as `250MiB` or `30GiB`. These are not aggregate limits
on expansion inside nested archives.

Additional bounds apply per image: at most one million layer entries and 64 MiB
of normalized entry-path text across all its layers, including filtered entries.
These bound the names retained for duplicate detection and historical path
tracking. After a layer's tar end marker, at most 16 MiB of zero padding is
accepted while validating the compression trailer and digest. Nonzero trailing
data is an error. This padding bound does not cap normal layer file contents.
JSON metadata input and each decoded representation are limited to 64 MiB;
image-index nesting is limited to 32, outer archives to one million entries,
each target to 10,000 manifest visits (including the root, repeated index
references, and failed child fetches),
zstd decoder memory to 256 MiB, and XZ dictionaries to 64 MiB. Limit failures
mark the scan incomplete. Local archives, layout metadata, and blobs must be
regular files; FIFOs and devices are rejected. Unsupported layer entry types
and malformed whiteouts also mark coverage incomplete.

Container scans use strict archive verification: missing or corrupt blobs,
unreadable nested archives, checksum failures, and exceeded limits mark JSON/JSONL
`scan.state` as `incomplete` and cause an unsuccessful exit. Findings already
collected are preserved, and independent content continues where possible.
Configured prefilter exclusions do not count as errors. Strict verification is
automatic for containers; there is no `--strict-archives` flag.

### Container SDK

Import `github.com/betterleaks/betterleaks/v2/sources/container` and pass the source
to the standard scanner or pipeline:

```go
src := &container.Source{
    Images:          []string{"ghcr.io/example/app:latest"},
    MaxArchiveDepth: 8,
    Prefilter:       compiledPrefilter,
}
summary, err := scanner.Scan(ctx, src, handleFinding)
```

`Archives` and `Layouts` select local inputs; set `Daemon` to `"docker"` or
`"podman"` to export `Images` through its HTTP API. Set `DaemonHost` for an explicit
endpoint and `DaemonTransport` for custom engine TLS or transport. The source
closes its own connections; caller-supplied transports remain caller-owned.
`Keychain` and `Transport` allow
custom registry authentication and HTTP transport, while `Anonymous` disables
credential lookup. The zero value of `MaxArchiveDepth` disables nested archive
traversal; the CLI supplies its default explicitly.

For direct `Fragments` callers, recoverable coverage failures arrive through the
callback's error argument. A non-nil callback return stops traversal. A nil
`Fragments` return does not mean full coverage if errors were yielded; the
standard scanner accounts for both error channels automatically.

---

## `validate` and `analyze`

Use `validate` to check a known credential's liveness. Use `analyze` to validate
it and then resolve identity and permissions. Both commands take an already
extracted credential and its rule ID, without running regexes, filters, or
source scanning. This is useful when the
original source is unavailable or a standalone credential no longer has the
provider context its detection regex expects.

Select the rule with `--rule <rule-id>` or `--rule=<rule-id>`; bare
`rule=<rule-id>` is not a flag. Analysis also reports observed capabilities and
severity derived from those capabilities, when available.

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

Use `stdin` for generated or piped content. It reads a plain byte stream;
unpack archives before piping them in. `--max-archive-depth` and
`--max-target-megabytes` do not apply to this command.

With terminal input, the command displays a waiting message and reads until
end-of-file. Ctrl-C cancels both plain and `--git-diff` stdin scans, including
when no input has arrived; canceled scans exit nonzero and reports are marked
incomplete.

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
betterleaks filesystem . -a --status valid,unknown

# validate without credential analysis
betterleaks filesystem . --validate --status valid

# detect without validation or analysis (the default)
betterleaks filesystem .

# cap and rate-limit outbound provider requests
betterleaks filesystem . -a \
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
