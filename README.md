# Betterleaks
```
 + ○
   ▾
```

Betterleaks is a configurable, fast, and thorough secrets scanner. It is maintained by the folks who made Gitleaks, including the original author.
Check out this series of blog posts to learn how the detection engine works: 1. [Regex is all you need](https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need), 2. [Rare Not Random](https://lookingatcomputer.substack.com/p/rare-not-random), 3. [Express YourCELf](https://lookingatcomputer.substack.com/p/express-yourcelf-filtering-and-validating), 4. [Better generic secrets detection](https://www.aikido.dev/blog/better-generic-secrets-detection-non-secrets).

Development is supported by
<a href="https://www.aikido.dev"><img src="docs/aikido_log.svg" alt="Aikido Security" width="80" /></a>

### Notable Features

| Feature | Description |
| :--- | :--- |
| **Expr-based filtering** | Write contextual rule filters that evaluate fragment (data chunks) attributes (like git author, commit message, and file path) and finding data to reduce false positives. |
| **Secrets Validation** | Validate if a detected secret is active by making asynchronous HTTP requests directly from within the rule definition using Expr. |
| **Secrets Analysis** | Enrich valid credentials with provider-neutral identity, account, capability, and severity information. |
| **BPE filtering** | Filter out natural language false positives by using BPE tokenization to measure how "rare" or non-human a string is. |
| **Fast scans** | Achieve fast performance through sane default parallelization settings, ahocorasick keyword filters, and re2. |
| **New Sources** | Support for sources like GitHub, GitLab, Hugging Face, S3, and more. It's easy to add new sources too!   |
| **Portability** | Runs on any modern OS/Arch. The small binary can be integrated in any system. |
| **Secrets Fingerprints** | Suppress reviewed secret values globally with exact SHA-256 entries in `.betterleaksignore`. |


### Installation
```
# Package managers
brew install betterleaks
brew install betterleaks/tap/betterleaks

# Fedora Linux
sudo dnf install betterleaks

# Containers
docker pull ghcr.io/betterleaks/betterleaks:latest

# Go
go install github.com/betterleaks/betterleaks/v2@latest

# Source
git clone https://github.com/betterleaks/betterleaks
cd betterleaks
make build
```

### Usage
```
# Scan Git
betterleaks git /path/to/repo -v -j 4

# Scan the filesystem
betterleaks /path/to/target
# Equivalent explicit command
betterleaks filesystem /path/to/target
# Short command alias
betterleaks fs /path/to/target

# Scan GitHub org
betterleaks github https://github.com/betterleaks
# Scan GitHub user
betterleaks github https://github.com/cooluser123456789 --include issues,prs,actions,releases,gists
# Scan specific resource, like a PR... but exclude the description (only scan comments)
betterleaks github https://github.com/betterleaks/betterleaks/pull/113

# Scan GitLab group or project
betterleaks gitlab https://gitlab.com/mygroup
betterleaks gitlab https://gitlab.com/mygroup/myproject --include issues,mrs,releases,ci-jobs
# Scan a specific GitLab merge request
betterleaks gitlab https://gitlab.com/mygroup/myproject/-/merge_requests/42

# Scan Hugging Face models, datasets, Spaces, and buckets
betterleaks huggingface https://huggingface.co/myorg
betterleaks hf https://huggingface.co/datasets/myorg/mydataset
betterleaks hf --include=discussions,prs https://huggingface.co/myorg/model
betterleaks hf hf://buckets/myorg/mybucket/path

# Scan a public s3 dataset (Common Crawl).
betterleaks s3 https://commoncrawl.s3.us-east-1.amazonaws.com/crawl-data/CC-MAIN-2018-17/segments/1524125937193.1/warc/
# Enumerate and scan every bucket in a Cloudflare R2 account
betterleaks s3 'https://<account-id>.r2.cloudflarestorage.com/*'

# Scan stdin
cat some_file.txt | betterleaks stdin -v

# Revalidate a known credential without running detection
printf '%s\n' "$GITHUB_TOKEN" | betterleaks validate --rule-id github-pat

# Print only its status (for example, VALID)
printf '%s\n' "$GITHUB_TOKEN" | betterleaks validate --rule-id github-pat --simple
```

For more advanced scanning examples check out the [scanning doc](docs/scanning.md).

### Go SDK

Betterleaks can also be embedded as a Go library. Scanners and analyzers are silent by
default and safe to reuse across scans.

```sh
go get github.com/betterleaks/betterleaks/v2
```

```go
package main

import (
	"fmt"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/scan"
)

func main() {
	cfg, err := config.Default()
	if err != nil {
		panic(err)
	}
	scanner, err := scan.New(cfg)
	if err != nil {
		panic(err)
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Println(finding.RuleID)
	}
}
```

`scan.Scanner` finds credentials locally. `analyze.Analyzer` determines whether
they work, who owns them, and what permissions they have. Detection confidence,
`Analysis.Status`, and permission-derived `Analysis.Severity` remain distinct
concepts. A finding groups matched text in `Match` and its optional path and
coordinates in `Location`.

Use `config.LoadFile` for custom rules and `scan.WithLogger` for diagnostics.
`Scanner.Scan` streams findings from a source; `Scanner.ScanString` handles small
inputs. Neither executes provider programs.

For an already-extracted secret:

```go
analyzer, err := analyze.New(cfg, analyze.WithTimeout(5*time.Second))
if err != nil {
    return err
}
result, err := analyzer.AnalyzeCredential(ctx, analyze.Credential{
    RuleID: "github-pat",
    Secret: token,
})
if err != nil {
    return err
}
// result.Analysis.Status describes liveness. The same Analysis also contains
// identity, capabilities, and derived severity when enrichment is available.
```

Call `analyzer.ValidateCredential` for liveness alone. Supply named `Captures`
and `Components` when required by the rule. Direct credential operations bypass
scan filters and sanitize supplied secret material in their reports.
`analyzer.Validate` and `analyzer.Analyze` accept existing `report.Finding` values
and return enriched findings without modifying the input.

Compose discovery and provider work with the pipeline:

```go
p, err := pipeline.New(scanner, analyzer,
    pipeline.WithValidationStatuses(report.ValidationStatusValid),
)
if err != nil {
    return err
}
summary, err := p.Scan(ctx, source, handler)
```

Detection and provider workers have independent concurrency limits and bounded
queues. Handlers run serially; returning an error cancels the operation and waits
for its workers. Status filters affect output, while the summary counts all
validation outcomes. A nil analyzer selects local discovery only. Remote sources
can still make requests to acquire their content.

Engines may be reused concurrently with independent sources. Each provider
operation owns its result caches and request limits; compiled programs are
reused. `scan.WithPrecompile` checks detection regexes and filters;
`analyze.WithPrecompile` checks validation and analysis programs. See the
[runnable analysis example](examples/with_analysis.go) and
[SDK architecture guide](docs/architecture.md).

Local inputs use `sources.Reader`, `sources.File`, `sources.Files`, and
`sources.Git`. Provider integrations have their own packages:

```go
import "github.com/betterleaks/betterleaks/v2/sources/github"

src := &github.Source{
    URL: "https://github.com/example/project",
    Token: token,
    ShouldSkip: scanner.SkipFunc(),
}
summary, err := scanner.Scan(ctx, src, handler)
```

GitLab, Hugging Face, and S3 use `sources/gitlab`, `sources/huggingface`, and
`sources/s3`, each with a `Source` type. Provider-specific constants live there
as well: `github.AttrOwner` and `github.ResourceIssue`, for example. Attribute
strings such as `"github.owner"` and `"github.issue"` are unchanged.

See the [`scan` package documentation](https://pkg.go.dev/github.com/betterleaks/betterleaks/v2/scan)
for complete default-config and custom-config examples.

### Configuration

Betterleaks' strength comes from its expressive configuration. Filtering,
validation, and analysis logic are defined as [Expr](https://expr-lang.org).
`prefilter`s run before any regex matching occurs and only have access to the
`attributes` map. `attributes` describe a resource like a git patch. Use
`prefilter`s to quickly bail out before more expensive scanning happens.
`filter`s, on the other hand, get evaluated post-regex match and have access to
the `attributes` map and candidate `finding` data like `finding["secret"]` or
`finding["match"]`.

```toml
# Global prefilter, it runs before expensive regex calls
prefilter = '''
matchesAny(attributes["path"], [
  `(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff|pdf|exe)$`,
  `(?:^|/)node_modules(?:/.*)?$`,
  `(?:^|/)vendor(?:/.*)?$`
])
|| attributes["git.author_name"] == "renovate[bot]"
'''

# Global filter, it runs for _every_ candidate secret.
filter = '''
containsAny(finding["secret"], [
  "EXAMPLE",
  "CHANGEME",
  "YOUR_API_KEY_HERE",
  "0000000000000000"
])
'''

# An array of tables that contain data on how to detect secrets
[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token, risking unauthorized repository access."
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]

# Rule-level filter
filter = '''
(
    attributes["git.author_name"] == "ci-runner" &&
    matchesAny(attributes["path"], [`^mocks/`]) &&
    finding["secret"] contains "TESTING"
)
|| (entropy(finding["secret"]) <= 3.0)
'''

# Post-match-and-filter async validation check
validate = '''
let r = http.get("https://api.github.com/user", {
    "Accept": "application/vnd.github+json",
    "Authorization": "token " + finding["secret"]
  });
r.status == 200 && (r.json?.login ?? "") != "" ? {
    "result": "valid",
    "analysis": {
      "id": string(r.json?.id ?? ""),
      "username": r.json?.login ?? "",
      "scopes": strings.splitTrim(r.headers["x-oauth-scopes"] ?? "", ",")
    }
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
'''

# Analyze valid credentials using data returned by validation
analyze = '''
let input = validation.analysis;
let scopes = input["scopes"] ?? [];
{
  "identity": {
    "id": input["id"] ?? "",
    "username": input["username"] ?? ""
  },
  "metadata": {"scopes": scopes},
  "capabilities": analysis.capabilities({
    "read": matchesAny(scopes, [
      "^read:",
      "^(?:gist|notifications|project|public_repo|repo(?::status)?|repo_deployment|security_events|user(?::email)?)$"
    ]),
    "write": matchesAny(scopes, [
      "^write:",
      "^delete:packages$",
      "^(?:gist|notifications|project|public_repo|repo(?::status)?|repo_deployment|workflow)$"
    ]),
    "create_credentials": matchesAny(scopes, [
      "^admin:(?:gpg_key|public_key|ssh_signing_key)$"
    ])
  })
}
'''
```

Multipart rules declare nearby component rules with `components` and read them
through `components["rule-id"]?.secret ?? ""` or
`components["rule-id"]?.captures?.group ?? ""`. Primary-rule named groups are
available through `finding["captures"]`.

Refer to the default [betterleaks config](https://github.com/betterleaks/betterleaks/blob/main/config/betterleaks.toml) for examples and the [config docs](docs/config.md) for more information about the `betterleaks.toml` config. If you're using Betterleaks in production, it is recommended you maintain your own config instead of extending the upstream default config directly. This keeps your rule set stable across Betterleaks upgrades and lets you review new upstream rules before adopting them.

See the [scanning guide](docs/scanning.md#ignore-exact-secret-values) for
`.betterleaksignore`, `--ignore-file`, and `betterleaks fingerprint`.

Test out your rules in the [Betterleaks Playground](https://betterleaks.com/playground)

### Who uses Betterleaks?
Projects and organizations that run Betterleaks. Open a pull request to add yours!
- [Aikido Security](https://www.aikido.dev/)
- [MegaLinter](https://megalinter.io) - open-source linter aggregator for CI, ships Betterleaks out of the box ([Betterleaks page](https://megalinter.io/latest/descriptors/repository_betterleaks/))
- [Moyai](https://moyai.ai/)
- [Entire.io](https://entire.io/)
- [LeakTK](https://github.com/leaktk)
