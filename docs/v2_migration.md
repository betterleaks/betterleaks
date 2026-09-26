# Migrating to Betterleaks v2

This guide covers migration from Betterleaks v1.8.1 to v2. Earlier v1 releases
may require additional changes. Use the [scanning guide](scanning.md) for source
options and the [configuration reference](config.md) for the complete rule and
expression contracts.

The most important changes are:

- **CLI scans validate and analyze credentials by default.** Add `--offline`
  to preserve detection-only behavior. SDK scanners still make no provider requests.
- **Select custom configs explicitly.** Target-local `.betterleaks.toml` files
  are no longer discovered automatically.
- **Update report consumers.** JSON has a new envelope and finding schema;
  JSONL includes a final scan summary.
- **Update SDK imports and construction.** The module is now
  `github.com/betterleaks/betterleaks/v2`; `scan.Scanner` replaces `detect.Detector`.

## Trying the release candidate

Once `v2.0.0-rc.1` is published, install that exact version:

```sh
go install github.com/betterleaks/betterleaks/v2@v2.0.0-rc.1
betterleaks version

# Or use the candidate container
docker pull ghcr.io/betterleaks/betterleaks:v2.0.0-rc.1
```

Release archives are also available on the
[releases page](https://github.com/betterleaks/betterleaks/releases).
The candidate does not update the Docker `latest` tag or Homebrew cask.

Start with your existing configuration and a local, offline scan:

```sh
betterleaks config check --config .betterleaks.toml
betterleaks fs . --config .betterleaks.toml --offline --redact -o results.json
```

Omit `--config` when using the embedded defaults. `config check` compiles regexes
and all expression blocks without executing provider requests. Fix its errors
before comparing findings with v1. Scans return exit code `1` for findings by
default; `--exit-code` changes that findings exit code.

## CLI changes

### Provider requests are on by default

In v1, scanning required `--validation` to contact credential providers. In v2:

| Scan mode | Behavior |
| :--- | :--- |
| Default | Validate supported credentials, then analyze valid credentials when the rule supports it. |
| `--no-analysis` | Validate only. |
| `--offline` | Detect and filter locally; disable both provider stages. |

`--offline` does not prevent downloading a remote scan target. Use a local
filesystem, local Git repository, or stdin when no source network access is wanted.
Revocation is separate: only an explicit `revoke` command runs a rule's `revoke`
expression. Scans never revoke credentials.

Use this command in pre-commit hooks:

```sh
betterleaks git --staged --offline --redact
```

### Commands and flags

| v1 command or flag | v2 replacement |
| :--- | :--- |
| `dir`, `directory`, `file` | `filesystem` or `fs` |
| `detect --source PATH` | `git PATH` |
| `detect --no-git --source PATH` | `fs PATH` |
| `detect --pipe` | `stdin` |
| `protect --source PATH`, `git --pre-commit PATH` | `git --unstaged PATH` |
| `protect --staged --source PATH` | `git --staged PATH` |
| `--validation` | Remove for validation and analysis; use `--no-analysis` for validation only. |
| `--validation-status` | `--status` |
| `--validation-workers`, `--validation-timeout`, `--validation-debug` | `--provider-workers`, `--provider-timeout`, `--provider-debug` |
| `--validation-max-requests`, `--validation-rps`, `--validation-rps-rule`, `--validation-env-vars` | Corresponding `--provider-*` flags. |
| `--git-workers` | Removed; sources choose their own I/O concurrency. Explicit `--log-opts` uses one history stream to preserve Git option semantics. `--jobs` / `-j` controls detection. |
| `--enable-rule` | `--isolate-rule` |
| `--ignore-gitleaks-allow` | `--no-allow-comments` |
| `--gitleaks-ignore-path` / `-i` | `--ignore-file PATH`, naming the file itself. See the ignore-format change below. |
| `--report-path` / `-r` | `--output` / `-o` |
| `--report-format=json` | `--output report.json`, or `--output -` for stdout. |
| `--report-format=jsonl` on `validate` | `--jsonl` |
| `--verbose` / `-v` | Remove: findings print by default. `-v` now prints the version. |
| `validate --rule-id ID` | `validate --rule ID` |
| `validate --list` | `config show ids --validation` |

`--legacy-print`, `--baseline-path`, `--report-template`, and the CSV, JUnit,
SARIF, and template reporters have been removed. There is no automatic baseline
conversion. `--experiments`, `--validation-extract-empty`, and the old global
`--timeout` flag are also gone. `--provider-timeout` limits individual provider
requests, not the entire scan. Use `--silent` / `-s` to suppress terminal findings
and the banner while still writing an explicitly requested report. The old
`-s` source-path shorthand is not retained.

Git diff modes scan **added lines**: `--staged` reads the index relative to HEAD;
`--unstaged` reads tracked working-tree changes relative to the index. They are
mutually exclusive. Neither scans untracked files; use `fs` for those.

You can now omit the command for a path or supported remote URL:

```sh
betterleaks ./project --offline
betterleaks https://github.com/owner/repo --offline
```

An existing local path selects filesystem scanning, even inside a Git checkout.
Use `git` explicitly for local history. For source selection, remote authentication,
and the new `url` command, see [automatic source selection](scanning.md#automatic-source-selection).

### New capabilities and scan coverage

- `analyze` validates a known credential and resolves supported identity and
  permissions. `revoke` explicitly invalidates a credential when its rule supports
  revocation. Find supporting rules with `config show ids --analysis` or
  `config show ids --revocation`.
- `config hash` identifies the resolved configuration or an individual rule;
  reports include these hashes for comparison.
- Reports stream findings and include scan state and summary counts. Binary and
  decoded findings have readable terminal previews and explicit decoding metadata.
- Files are no longer skipped solely by MIME type. The default prefilter no
  longer excludes `.git` or the broad document/executable extension group;
  image, font, and other configured exclusions still apply. A filesystem scan
  can therefore inspect more bytes and produce more findings than v1. Scanning
  binary bytes is not document text extraction, and scanning `.git` as files is
  not a substitute for `git` history scanning.

GitHub, GitLab, Hugging Face, and S3 sources already existed in v1. See the
[scanning guide](scanning.md#pick-a-target) for their current resource coverage.

## Configuration changes

### Config selection is explicit

The CLI resolves one configuration for the entire invocation, in this order:

1. `--config` / `-c`.
2. `BETTERLEAKS_CONFIG` (a file path).
3. `BETTERLEAKS_CONFIG_TOML` (inline TOML).
4. Embedded defaults.

Rename `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` environment variables to their
`BETTERLEAKS_*` equivalents. Neither `.betterleaks.toml` nor `.gitleaks.toml` is
automatically loaded from a target or the working directory. If different targets
need different configs, scan them in separate invocations.

### Legacy fields are rejected

Unknown TOML fields now fail loading, including fields in inherited configs.
Remove compatibility fields rather than leaving them alongside their replacements.

| v1 configuration | v2 replacement |
| :--- | :--- |
| Global or rule `allowlist` / `allowlists` | Explicit `prefilter` / `filter` expressions. |
| Rule `entropy = 3.5` | `filter = 'entropy(finding.secret) <= 3.5'` |
| Rule `tokenEfficiency = true` | `filter = 'failsTokenEfficiency(finding.secret)'` |
| `[[rules.required]]` with `withinLines` / `withinColumns` | `components = [{ id = "other-rule", within = "5L,100C" }]` for those example bounds. |
| `betterleaksMinVersion` | `minVersion`, now a minimum **Betterleaks** version. |

Do not carry over a Gitleaks `minVersion = "8.x.y"`: it now means Betterleaks
8.x.y. For a config requiring this candidate, use `minVersion = "2.0.0-rc.1"`.
`2.0.0` requires the final release and excludes its release candidates.

A filter returning `true` **discards** the input. Combine skip conditions with
`||`, preserving any existing filter. For example, replace this v1 rule:

```toml
[[rules]]
id = "example-token"
regex = '''example_[A-Za-z0-9]{32}'''
entropy = 3.5
tokenEfficiency = true
```

with:

```toml
[[rules]]
id = "example-token"
regex = '''example_[A-Za-z0-9]{32}'''
filter = '''
entropy(finding.secret) <= 3.5 || failsTokenEfficiency(finding.secret)
'''
```

Move whole-source path or commit exclusions into the global `prefilter`; use
global or rule `filter` expressions for secret, match, or line exclusions. Preserve
the original allowlist's AND/OR grouping and regex target when translating it.
See [filtering](config.md#filtering).

### Inherited rules are replaced, not merged

A child rule with the same ID as an inherited rule replaces the **entire rule**.
An override containing only an ID and description is no longer valid. Copy the
full rule you want to retain, including its regex/path, keywords, filters,
components, and provider expressions, then edit it. Omitted fields do not inherit
their previous values, and lists are not concatenated.

Global `prefilter` and `filter` expressions remain additive across inheritance:
either config may discard an input. Duplicate rule IDs within one file are errors.
`extend.path` is relative to the working directory; `extend.url` is unsupported.
See [configuration structure and inheritance](config.md#top-level-shape).

### Expression inputs and results

v1.8.1 already used Expr. v2 removes legacy aliases and narrows provider inputs:

| Old expression form | v2 form |
| :--- | :--- |
| `filter.entropy(value)` and other `filter.*` helpers | `entropy(value)` and other top-level helpers. |
| Top-level `secret` | `finding.secret` |
| Top-level `captures["name"]` | `finding.captures["name"]` for primary captures. |
| Component values mixed into `captures` | `components["rule-id"].secret` and `.captures["name"]`. |

Provider expressions (`validate`, `analyze`, `revoke`) receive credential data,
not paths, source attributes, lines, or context. Keep occurrence-based decisions
in local filters. Optional component access should use `?.` and `??`.
The [helper migration table](config.md#native-expr-helpers-and-migration) lists
removed function aliases and replacements, including native Expr helpers.

Validation results are closed objects: use `result`, optional `reason`, public
`metadata`, and an optional private `analysis` object passed to the subsequent
analysis expression. Move arbitrary top-level result fields into `metadata`:

```expr
// v1
{"result": "valid", "account": "demo"}

// v2
{"result": "valid", "metadata": {"account": "demo"}}
```

An `analyze` expression requires `validate` and runs only for valid credentials.
It reads the validation result through `validation` and returns structured
identity/capability information. See [validation and analysis](config.md#validation-and-credential-analysis)
and [explicit revocation](config.md#explicit-credential-revocation).

### Ignore files

v2 `.betterleaksignore` entries are bare SHA-256 digests (64 hexadecimal
characters) over the exact secret bytes. The `sha256:` prefix is not accepted.
They suppress that primary secret and exclude matching component values across
rules, paths, commits, and sources. If a required component has no
remaining matches, the primary is suppressed. Ignored optional components are
treated as absent, so the primary survives without them.
Legacy location fingerprints and `.gitleaksignore` discovery are
not supported; regenerate entries from the original secret values:

```sh
printf '%s' "$SECRET" | betterleaks fingerprint
```

Do not hash a redacted value or add a trailing newline. Existing `betterleaks:allow`
and `gitleaks:allow` comments still work. See [ignore semantics and discovery](scanning.md#ignore-exact-secret-values).

## Report changes

CLI JSON output is an object with `schema_version`, `findings`, and `scan`,
instead of a bare finding array. Read `.findings[]` rather than `.[]`.
The schema version is the string `"1"`: it versions this new report contract
independently of the Betterleaks major version.

JSONL emits one `{"schema_version":"1","finding":{...}}` envelope per finding,
then a final `{"schema_version":"1","scan":{...}}` record, even for zero findings.
Consumers must distinguish the two record types. For example:

```sh
jq '.findings[] | .rule_id' results.json
jq -c 'select(has("finding")) | .finding' results.jsonl
```

The Go fields and serialized names have changed together:

| v1 finding field | v2 Go field | v2 JSON field |
| :--- | :--- | :--- |
| `RuleID` | `RuleID` | `rule_id` |
| `Secret` | `Match.Value` | `match.value` |
| `Match` | `Match.Full` | `match.full` |
| `CaptureGroups` | `Match.Captures` | `match.captures` |
| `MatchContext` | `Match.Context` | `match.context` |
| `File`, `StartLine`, `StartColumn`, etc. | `Location.Path`, `Location.StartLine`, `Location.StartColumn`, etc. | `location.path`, `location.start_line`, `location.start_column`, etc. |
| `ValidationStatus`, `ValidationReason`, `ValidationMeta` | `Analysis.Status`, `Analysis.StatusReason`, `Analysis.StatusMetadata` | `analysis.status`, `analysis.status_reason`, `analysis.status_metadata` |
| `Commit`, `Author`, etc. | Source metadata in `Attributes` | `attributes`, using keys such as `git.sha` and `git.author_name`. |

The legacy location-based `Fingerprint` is replaced by `Match.Fingerprint`
(`match.fingerprint` in JSON): SHA-256 of the original `match.value` bytes as
64 lowercase hexadecimal characters without a prefix, in `.betterleaksignore`
format. It is included on non-empty primary and component matches, including
non-secret components such as account IDs, and preserved through redaction and
analysis. `Entropy` and `Fragment` fields are gone. `tags` remains
available for rule labels and is omitted when empty. Decoding uses `encodings`
and `decode_depth`, not generated `decoded:*` tags. Source coordinates point to
the encoded input; `match.value` contains the extracted secret. JSON encoding
replaces invalid UTF-8 bytes with U+FFFD, so reports are not a lossless binary format.

`scan` records state (`complete` or `incomplete`), source targets, start/finish
times, Betterleaks version, config hash, inspected bytes, finding count, and
confidence/severity/status counts. A completed scan can still have findings or
warnings about skipped inputs. Provider status `error` alone does not make the
scan incomplete. An incomplete report retains findings emitted before failure.

See [finding output](scanning.md#finding-output) and the linked JSON Schemas for
the full contract. Direct `validate`, `analyze`, and `revoke` output uses the
separate credential report. Low-level SDK `report.WriteJSON` still writes a bare
array; `report.WriteJSONL` writes finding envelopes. Neither adds CLI scan metadata.

## Go SDK changes

Update all imports to `/v2` and use Go 1.25 or newer:

```sh
go get github.com/betterleaks/betterleaks/v2@v2.0.0-rc.1
```

### Replace Detector with Scanner and explicit sources

`detect.Detector`, its mutable runtime/reporting fields, and its channel-based
`Run` API are removed. Construct a scanner with options, supply a source, and
consume findings with a callback. This complete example scans memory without
provider requests and reports scan errors:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	scanner, err := scan.New(cfg)
	if err != nil {
		return err
	}
	skip, err := prefilter.Compile(cfg.Prefilter, prefilter.Options{})
	if err != nil {
		return err
	}
	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	source := &sources.Reader{
		Content:    strings.NewReader("GITHUB_TOKEN=" + token),
		Attributes: map[string]string{sources.AttrPath: "application.env"},
		ShouldSkip: skip,
	}
	summary, err := scanner.Scan(context.Background(), source, func(f report.Finding) error {
		_, err := fmt.Println(f.RuleID, f.Location.Path)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Printf("Inspected %d bytes; found %d secrets\n", summary.BytesInspected, summary.Findings)
	return nil
}
```

Source prefilters are explicit: compile `cfg.Prefilter` and set the source's
`ShouldSkip`. The scanner does not apply it for you. Archive depth, file-size
limits, and symlink handling belong to sources; detection options belong to
`scan.New`. Use `sources.Git{RepoPath: ".", Mode: sources.GitStaged}` for staged
changes instead of constructing Git commands or sharing a detector semaphore.

Callbacks are serialized within a scan; returning an error stops it. Finding
order is not guaranteed. Reuse scanners across concurrent calls with independent
sources. `ScanString` remains convenient for small strings, but cannot return
scan errors; use `Scan` when failures must be observable. Callers own
`sources.Reader.Content` and must close or cancel it to interrupt a blocked read.

### Config is data; engines own execution

`Config.Rules` is now `[]config.Rule`, not a map. `Rule.RuleID` becomes `Rule.ID`;
`Rule.Regex` and `Rule.Path` are pattern strings, not compiled regex objects.
Components are `[]config.Component`. Keyword indexes and compiled expression
programs are no longer public config state. Use `config.Default`, `LoadFile`,
`ParseTOML`, or `ParseTOMLString`, or construct the data directly.

Constructors return errors and snapshot the config. Finish edits before calling
`scan.New` / `analyze.New`; construct new engines when rules change. Finding
filters compile in `scan.New`; detection regexes and validation/analysis programs
normally compile lazily. `scan.WithPrecompile()` and `analyze.WithPrecompile()`
check those programs at construction. Neither substitutes for compiling source
prefilters or checking a rule's `revoke` expression.

### Provider work is an explicit opt-in

`scan.New(cfg)` never runs `validate`, `analyze`, or `revoke` expressions.
To validate and analyze discoveries, construct `analyze.New(cfg)` and combine
it with the scanner using `pipeline.New(scanner, analyzer)`, then call the
pipeline's `Scan` method. Use `pipeline.WithValidationOnly()` for validation
without enrichment. For already extracted credentials, use
`Analyzer.ValidateCredential` or `Analyzer.AnalyzeCredential` with `credential.Input`.

Configure detection workers with `scan.WithWorkers`, and provider workers and
request limits with `analyze` options. Sources use internal concurrency limits;
their `Workers` fields have been removed. See [parallel jobs](scanning.md#parallel-jobs).
Scanners and analyzers are silent by default; inject `*slog.Logger` through their
`WithLogger` options. Reporting and redaction belong to your application; use
`Finding.RedactedCopy` when exporting findings that should hide credentials.

See the runnable [detection-only](../examples/without_analysis.go),
[analysis pipeline](../examples/with_analysis.go), and
[custom config](../examples/custom_config.go) examples.

### Regex selection no longer uses a global engine

The SDK defaults to Go's standard-library regex engine. It does not require
importing RE2/Wazero. Opt in through the separate package:

```go
// Import "github.com/betterleaks/betterleaks/v2/regexp/re2".
scanner, err := scan.New(cfg, scan.WithRegexEngine(re2.RE2{}))
```

The choice is local to each engine: configure `analyze.WithRegexEngine` for
provider regex helpers and `prefilter.Options.RegexEngine` for source prefilters
if they should also use RE2. There is no process-wide `regexp.SetEngine`.
The CLI still defaults to RE2; use `--regex-engine stdlib` to select stdlib there.
See the [RE2 SDK example](../examples/with_re2_regexp.go).

### Configuration identity for caches

Use `cfg.Hash()` for the resolved configuration, `cfg.RuleHash(id)` for one rule
and its components, or `cfg.RuleHashes()` for all rules. CLI equivalents are:

```sh
betterleaks config hash --config custom.toml
betterleaks config hash --config custom.toml --rule github-pat
```

Findings carry `rule_hash`; CLI scan metadata carries `config_hash`. Both hashes
include provider expressions as well as detection settings. They identify
configuration, not input content, runtime options, or live provider state. Keep
those other dependencies in your cache key or freshness policy. See
[configuration hashes](config.md#configuration-hashes-for-sdk-caches).
