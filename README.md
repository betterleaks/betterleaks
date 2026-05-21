# Betterleaks
```
  ○
  ○
  ●
  ○
```

Betterleaks is a tool for finding secrets like passwords and API keys. If you want to learn more about how the detection engine works check out this blog: [Regex is (almost) all you need](https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need).

Betterleaks is maintained by the folks who made Gitleaks, including the original author. Development is supported by <a href="https://www.aikido.dev">Aikido Security</a>
<br><a href="https://www.aikido.dev"><img src="docs/aikido_log.svg" alt="Aikido Security" width="80" /></a>

### Notable Features

| Feature | Description |
| :--- | :--- |
| **CEL-based filtering** | Write contextual rule filters that evaluate fragment (data chunks) attributes (like git author, commit message, and file path) and finding data to reduce false positives. If you're coming from Gitleaks, think of this feature as a more expressive `[[allowlist]]` system. |
| **Secrets Validation** | Validate if a detected secret is active by making asynchronous HTTP requests directly from within the rule definition using CEL. |
| **Token Efficiency filtering** | Filter out natural language false positives by using BPE tokenization to measure how "rare" or non-human a string is. |
| **Fast scans** | Achieve fast performance through sane default parallelization settings, ahocorasick keyword filters, and re2. |
| **Portability** | Runs on any modern OS/Arch. The small binary can be integrated in any system. |


### Installation
```
# Package managers
brew install betterleaks
brew install betterleaks/tap/betterleaks

# Fedora Linux
sudo dnf install betterleaks

# Containers
docker pull ghcr.io/betterleaks/betterleaks:latest

# Source
git clone https://github.com/betterleaks/betterleaks
cd betterleaks
make build
```

### Usage
```
# Scan Git
betterleaks git /path/to/repo -v --git-workers=16

# Scan local filesystem
betterleaks dir /path/to/file/or/dir -v

# Scan GitHub org
betterleaks github https://github.com/betterleaks
# Scan GitHub user
betterleaks github https://github.com/cooluser123456789 --include issues,prs,actions,releases,gists
# Scan specific resource, like a PR... but exclude the description (only scan comments)
betterleaks github https://github.com/betterleaks/betterleaks/pull/113

# Scan a public s3 dataset (Common Crawl).
betterleaks s3 https://commoncrawl.s3.us-east-1.amazonaws.com/crawl-data/CC-MAIN-2018-17/segments/1524125937193.1/warc/
# Enumerate and scan every bucket in a Cloudflare R2 account
betterleaks s3 'https://<account-id>.r2.cloudflarestorage.com/*'

# Scan stdin
cat some_file.txt | betterleaks stdin -v
```

For more advanced scanning examples check out the [scanning doc](docs/scanning.md).

### Configuration

Betterleaks' strength comes from its expressive configuration. Filtering and validation logic are defined as CEL. It is recommended you spend 30 minutes familiarizing yourself with [CEL](https://cel.dev) before writing filters and validators. `prefilter`s run before any regex matching occurs and only have access to the `attributes` map. `attributes` describe a resource like a git patch. Use `prefilter`s to quickly bail out before more expensive scanning happens. `filter`s, on the other hand, get evaluated post-regex match and have access to the `attributes` map and candidate `finding` data like `finding["secret"]` or `finding["match"]`.

```toml
# Global prefilter, it runs before expensive regex calls
prefilter = '''
(matchesAny(attributes[?"path"].orValue(""), [
  r"""(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff|pdf|exe)$""",
  r"""(?:^|/)node_modules(?:/.*)?$""",
  r"""(?:^|/)vendor(?:/.*)?$"""
]))
|| attributes[?"git.author_name"].orValue("") == "renovate[bot]"
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
id = "github-fine-grained-pat"
description = "GitHub Fine-Grained Personal Access Token, risking unauthorized repo access."
regex = '''github_pat_\w{82}'''
keywords = ["github_pat_"]

# Rule-level filter
filter = '''
(
    attributes[?"git.author_name"].orValue("") == "ci-runner" &&
    attributes[?"path"].orValue("").startsWith("mocks/") &&
    finding["secret"].contains("TESTING")
)
|| (entropy(finding["secret"]) <= 3.0)
'''

# Post-match-and-filter async validation check
validate = '''
cel.bind(r,
  http.get("https://api.github.com/user", {
    "Accept": "application/vnd.github+json",
    "Authorization": "token " + secret
  }),
  r.status == 200 && r.json.?login.orValue("") != "" ? {
    "result": "valid",
    "username": r.json.?login.orValue(""),
    "name": r.json.?name.orValue(""),
    "scopes": r.headers[?"x-oauth-scopes"].orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)
'''
```

Refer to the default [betterleaks config](https://github.com/betterleaks/betterleaks/blob/main/config/betterleaks.toml) for examples and the [config docs](docs/config.md) for more information about the `betterleaks.toml` config.

### Exit Codes

Set the exit code when leaks are encountered with the --exit-code flag. Default exit codes below:

```
0 - no leaks present
1 - leaks or error encountered
126 - unknown flag
```

