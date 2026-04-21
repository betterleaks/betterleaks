# Betterleaks
```
  ○
  ○
  ●
  ○  
```

Betterleaks is a tool for finding secrets like passwords, API keys, and tokens. If you want to learn more about how the detection engine works check out this blog: [Regex is (almost) all you need](https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need).

Betterleaks development is supported by <a href="https://www.aikido.dev">Aikido Security</a>
<br><a href="https://www.aikido.dev"><img src="docs/aikido_log.svg" alt="Aikido Security" width="80" /></a>



Wait wtf this isn't Gitleaks. You're right, it's not but it's built by the same people who maintained Gitleaks and ships with some cool new features.

### Notable Features

| Feature | Description |
| :--- | :--- |
| **CEL-based filtering** | Write contextual rule filters that evaluate fragment (data chunks) attributes (like git author, commit message, and file path) and finding data to drastically reduce false positives. |
| **Secrets Validation** | Automatically verify if a detected secret is active by making asynchronous HTTP requests directly from within the rule definition using CEL. |
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

# Scan stdin
cat some_file.txt | betterleaks stdin -v
```

### Configuration

Betterleaks' strength comes from its expressive configuration. The majority of that expressiveness comes from the fact that rule filtering and validation logic are defined as CEL expressions. It is recommended you spend 30 minutes familiarizing yourself with [CEL](https://cel.dev) before writing filters and validators. 

```toml
# Prefilters run BEFORE any regex matching occurs, hence the _pre_.
# They only have access to the `attributes` map (like file path and git metadata).
# Use this to quickly bypass heavy binary files, vendor directories, or noisy bots.
prefilter = '''
(matchesAny(attributes[?"path"].orValue(""), [
  r"""(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff|pdf|exe)$""",
  r"""(?:^|/)node_modules(?:/.*)?$""",
  r"""(?:^|/)vendor(?:/.*)?$"""
]))
|| attributes[?"git.author_name"].orValue("") == "renovate[bot]"
'''

# Filters run AFTER a regex match is found. 
# Source `attributes` AND `finding` data is available to compare against.
# If this expression evaluates to true, the finding is discarded.
# This is a GLOBAL filter, it runs for _every_ candidate secret.
filter = '''
containsAny(finding["secret"], [
  "EXAMPLE",
  "CHANGEME",
  "YOUR_API_KEY_HERE",
  "0000000000000000"
])
'''

# An array of tables that contain information that define instructions
# on how to detect secrets
[[rules]]
id = "github-fine-grained-pat"
description = "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation."
regex = '''github_pat_\w{82}'''
keywords = ["github_pat_"]
# The validation block uses CEL to actively call the GitHub API and verify if the token is live.
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
# We can override the rule's filter to add our own highly specific business logic.
# Here we keep the baseline entropy check, but also add a contextual scenario:
# "Ignore this GitHub PAT if it's in a mock file authored by our CI user, and contains 'TESTING'."
filter = '''
(
    attributes[?"git.author_name"].orValue("") == "ci-runner" &&
    attributes[?"path"].orValue("").startsWith("mocks/") &&
    finding["secret"].contains("TESTING")
)
|| (entropy(finding["secret"]) <= 3.0)
'''

[[rules]]
id = "awesome-rule-2"
# ... etc etc etc
```

Refer to the default [betterleaks config](https://github.com/betterleaks/betterleaks/blob/master/config/betterleaks.toml) for examples or follow the [contributing guidelines](https://github.com/betterleaks/betterleaks/blob/master/CONTRIBUTING.md) if you would like to contribute to the default configuration.

### Exit Codes

You can always set the exit code when leaks are encountered with the --exit-code flag. Default exit codes below:

```
0 - no leaks present
1 - leaks or error encountered
126 - unknown flag
```

