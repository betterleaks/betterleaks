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
| **Simple Prioritization** | Rank by confidence, validation status, and analyzed severity scores to make triage as simple as 123. |
| **Secrets Validation** | Validate if a detected secret is active by making asynchronous HTTP requests directly from within the rule definition using Expr. |
| **Secrets Analysis** | Enrich valid credentials with provider-neutral identity, account, capability, and severity information. |
| **Secrets Revocation** | Optionally revoke secrets. |
| **Expr-based filtering** | Write contextual rule filters that evaluate fragment (data chunks) attributes (like git author, commit message, and file path) and finding data to reduce false positives. |
| **BPE filtering** | Filter out natural language false positives by using BPE tokenization to measure how "rare" or non-human a string is. |
| **Fast scans** | Achieve fast performance through sane default parallelization settings, ahocorasick keyword filters, and re2. |
| **New Sources** | Support for sources like GitHub, GitLab, Hugging Face, S3, and more. It's easy to add new sources too!   |
| **Portability** | Runs on any modern OS/Arch. The small binary can be integrated in any system. |


### Installation

The `main` branch is for v2 development. V1 maintenance and documentation live on the [`v1.x` branch](https://github.com/betterleaks/betterleaks/tree/v1.x).

Upgrading from v1? See the [v2 migration guide](docs/v2_migration.md) for CLI, config, report, and SDK changes.

Until the first stable v2 release, package managers and the Docker `latest` tag
may still provide v1. Use the migration guide's [release candidate instructions](docs/v2_migration.md#trying-the-release-candidate)
to try v2 before then.

```
# Package managers
brew install betterleaks
brew install --cask betterleaks/tap/betterleaks

# Fedora Linux
sudo dnf install betterleaks

# Containers (stable v2)
docker pull ghcr.io/betterleaks/betterleaks:v2

# Go
go install github.com/betterleaks/betterleaks/v2@latest

# Source
git clone https://github.com/betterleaks/betterleaks
cd betterleaks
make build
```

Stable v2 releases update the tap's `betterleaks` cask and Docker `:v2` and
`:latest` tags. Homebrew core updates separately. To keep v1 installed alongside
v2, use `brew install --cask betterleaks/tap/betterleaks@1` (command:
`betterleaks-v1`) or the Docker `:v1` tag.

### Usage

Scans detect secrets without credential provider requests by default. Use
`-v` / `--validate` to check credentials, or `-a` / `--analyze` to also resolve
identity and permissions. Analysis implies validation. Set `BETTERLEAKS_VALIDATE=true` or `BETTERLEAKS_ANALYZE=true` to enable these stages through the environment. Explicit flags override the corresponding variable.

```
# Scan the filesystem
betterleaks /path/to/target
# Equivalent explicit command
betterleaks filesystem /path/to/target
# Short command alias
betterleaks fs /path/to/target
# Flags may also precede the command
betterleaks --no-banner fs /path/to/target

# Validate detected credentials
betterleaks fs /path/to/target -v
# Validate and analyze identity and permissions
betterleaks fs /path/to/target -a

# Scan a git repo
betterleaks git /path/to/repo

# Automatically detect a remote repository and scan its history
betterleaks https://github.com/betterleaks/betterleaks
# The default command can also be named explicitly
betterleaks auto https://github.com/betterleaks/betterleaks
# Explicitly download and scan a web response (without crawling)
betterleaks url https://example.com/config.txt

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
cat some_file.txt | betterleaks stdin

# Revalidate a known credential without running detection
printf '%s\n' "$GITHUB_TOKEN" | betterleaks validate --rule github-pat

# Find rule IDs that support credential analysis
betterleaks config show ids --analysis

# Validate it and resolve identity and permissions
printf '%s\n' "$GITHUB_TOKEN" | betterleaks analyze --rule github-pat

# Print only its status (for example, VALID)
printf '%s\n' "$GITHUB_TOKEN" | betterleaks validate --rule github-pat --simple
```

Use `--hmac-key` or `BETTERLEAKS_FINGERPRINT_HMAC_KEY` for keyed match fingerprints;
see [fingerprint privacy and key setup](docs/scanning.md#ignore-exact-secret-values).

`-j` / `--jobs` controls detection concurrency only, defaulting to `4 * GOMAXPROCS`.
Sources manage their own
bounded reads and downloads; Git uses one history stream when `--log-opts` is
provided. See [parallel jobs](docs/scanning.md#parallel-jobs)
and the [scanning guide](docs/scanning.md) for details and more examples.

Rules may also define an optional `revoke` Expr for explicit credential revocation.
Use `betterleaks config show ids --revocation` to find configured support and
`betterleaks revoke --rule <id>` to execute it. Scans never run revocation.
See the [revocation guide](docs/config.md#explicit-credential-revocation).

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

See the [examples directory](examples/) for runnable SDK examples covering custom configuration, analysis, regex engines, and concurrent scanning.

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
- [CodeRabbit](https://www.coderabbit.ai/)
- [Nhost](https://github.com/nhost/nhost)
- [Atlas](https://github.com/pacifio/atlas)
- [Kingfisher](https://github.com/mongodb/kingfisher)
- [Chainloop](https://github.com/chainloop-dev/chainloop)
- [Chezmoi](https://github.com/twpayne/chezmoi)
- [Pipeleek](https://github.com/CompassSecurity/pipeleek)
