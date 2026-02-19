# Betterleaks

Betterleaks is a tool for **detecting** secrets like passwords, API keys, and tokens in git repos, files, and whatever else you wanna throw at it via `stdin`. If you wanna learn more about how the detection engine works check out this blog: [Regex is (almost) all you need](https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need).

```
➜  ~/code(master) betterleaks git -v


  ○
  ○
  ●
  ○  Betterleaks v1.0.0

  Finding:     "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
  Secret:      cafebabe:deadbeef
  RuleID:      sidekiq-secret
  Entropy:     2.609850
  File:        cmd/generate/config/rules/sidekiq.go
  Line:        23
  Commit:      cd5226711335c68be1e720b318b7bc3135a30eb2
  Author:      John
  Email:       john@users.noreply.github.com
  Date:        2022-08-03T12:31:40Z
```

Wait wtf this isn't Gitleaks. You're right, it's not but it's built by the same people who maintained Gitleaks and ships with some cool new features.

## What's New?
A couple things:
- Parallelized Git Scanning (`--git-workers=`)
- Optimized Recursive Decoding (for catching those nasty SHA1-HULUD variants)
- Token Efficiency Filter (a better entropy)
- Misc optimizations
- Regex engine switching w/ (`--regexp-engine=re2`)

## What's Coming?
Great question. Check out what we're cookin in the v2 branch.

## Installation
TODO

## Usage

```
Betterleaks scans code, past or present, for secrets

Usage:
  betterleaks [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dir         scan directories or files for secrets
  git         scan git repositories for secrets
  help        Help about any command
  stdin       detect secrets from stdin
  version     display gitleaks version

Flags:
  -b, --baseline-path string          path to baseline with issues that can be ignored
  -c, --config string                 config file path
                                      order of precedence:
                                      1. --config/-c
                                      2. env var BETTERLEAKS_CONFIG or GITLEAKS_CONFIG
                                      3. env var BETTERLEAKS_CONFIG_TOML or GITLEAKS_CONFIG_TOML with the file content
                                      4. (target path)/.betterleaks.toml or .gitleaks.toml
                                      If none of the four options are used, then the default config will be used
      --diagnostics string            enable diagnostics (http OR comma-separated list: cpu,mem,trace). cpu=CPU prof, mem=memory prof, trace=exec tracing, http=serve via net/http/pprof
      --diagnostics-dir string        directory to store diagnostics output files when not using http mode (defaults to current directory)
      --enable-rule strings           only enable specific rules by id
      --exit-code int                 exit code when leaks have been encountered (default 1)
  -i, --gitleaks-ignore-path string   path to .betterleaksignore or .gitleaksignore file or folder containing one (default ".")
  -h, --help                          help for betterleaks
      --ignore-gitleaks-allow         ignore betterleaks:allow and gitleaks:allow comments
  -l, --log-level string              log level (trace, debug, info, warn, error, fatal) (default "info")
      --max-archive-depth int         allow scanning into nested archives up to this depth (default "0", no archive traversal is done)
      --max-decode-depth int          allow recursive decoding up to this depth (default "0", no decoding is done)
      --max-target-megabytes int      files larger than this will be skipped
      --no-banner                     suppress banner
      --no-color                      turn off color for verbose output
      --redact uint[=100]             redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)
  -f, --report-format string          output format (json, csv, junit, sarif, template)
  -r, --report-path string            report file
      --report-template string        template file used to generate the report (implies --report-format=template)
      --timeout int                   set a timeout for betterleaks commands in seconds (default "0", no timeout is set)
  -v, --verbose                       show verbose output from scan
      --version                       version for betterleaks

Use "betterleaks [command] --help" for more information about a command.
```

### Commands

#### Git

The `git` command lets you scan local git repos. Under the hood, betterleaks uses the `git log -p` command to scan patches.
You can configure the behavior of `git log -p` with the `log-opts` option.
For example, if you wanted to run betterleaks on a range of commits you could use the following
command: `betterleaks git -v --log-opts="--all commitA..commitB" path_to_repo`. See the [git log](https://git-scm.com/docs/git-log) documentation for more information.
If there is no target specified as a positional argument, then betterleaks will attempt to scan the current working directory as a git repo.

If you want faster `git` scans you can enable parallelized `git log -p` with `--git-workers={int}`.

#### Dir

The `dir` (aliases include `files`, `directory`) command lets you scan directories and files. Example: `betterleaks dir -v path_to_directory_or_file`.
If there is no target specified as a positional argument, then betterleaks will scan the current working directory.

#### Stdin

You can also stream data to betterleaks with the `stdin` command. Example: `cat some_file | betterleaks -v stdin`

### Creating a baseline

When scanning large repositories or repositories with a long history, it can be convenient to use a baseline. When using a baseline,
betterleaks will ignore any old findings that are present in the baseline. A baseline can be any betterleaks report. To create a report, run betterleaks with the `--report-path` parameter.

```
betterleaks git --report-path betterleaks-report.json # This will save the report in a file called betterleaks-report.json
```

Once as baseline is created it can be applied when running the detect command again:

```
betterleaks git --baseline-path betterleaks-report.json --report-path findings.json
```

After running the detect command with the --baseline-path parameter, report output (findings.json) will only contain new issues.


## Load Configuration

Betterleaks supports both `betterleaks` and `gitleaks` naming conventions for backwards compatibility. The `betterleaks` variants take precedence.

The order of precedence is:

1. `--config/-c` option:
      ```bash
      betterleaks git --config /home/dev/customconfig.toml .
      ```
2. Environment variable `BETTERLEAKS_CONFIG` or `GITLEAKS_CONFIG` with the file path:
      ```bash
      export BETTERLEAKS_CONFIG="/home/dev/customconfig.toml"
      betterleaks git .
      ```
3. Environment variable `BETTERLEAKS_CONFIG_TOML` or `GITLEAKS_CONFIG_TOML` with the file content:
      ```bash
      export BETTERLEAKS_CONFIG_TOML=`cat customconfig.toml`
      betterleaks git .
      ```
4. A `.betterleaks.toml` or `.gitleaks.toml` file within the target path:
      ```bash
      betterleaks git .
      ```

If none of the four options are used, then the default config will be used.

## Configuration

Betterleaks offers a configuration format you can follow to write your own secret detection rules:

```toml
# Title for the Betterleaks configuration file.
title = "Custom Betterleaks configuration"

# You have basically two options for your custom configuration:
#
# 1. define your own configuration, default rules do not apply
#
#    use e.g., the default configuration as starting point:
#    https://github.com/betterleaks/betterleaks/blob/master/config/betterleaks.toml
#
# 2. extend a configuration, the rules are overwritten or extended
#
#    When you extend a configuration the extended rules take precedence over the
#    default rules. I.e., if there are duplicate rules in both the extended
#    configuration and the default configuration the extended rules or
#    attributes of them will override the default rules.
#    Another thing to know with extending configurations is you can chain
#    together multiple configuration files to a depth of 2. Allowlist arrays are
#    appended and can contain duplicates.

# useDefault and path can NOT be used at the same time. Choose one.
[extend]
# useDefault will extend the default gitleaks config built in to the binary
# the latest version is located at:
# https://github.com/betterleaks/betterleaks/blob/master/config/betterleaks.toml
useDefault = true
# or you can provide a path to a configuration to extend from.
# The path is relative to where gitleaks was invoked,
# not the location of the base config.
# path = "common_config.toml"
# If there are any rules you don't want to inherit, they can be specified here.
disabledRules = [ "generic-api-key"]

# An array of tables that contain information that define instructions
# on how to detect secrets
[[rules]]
# Unique identifier for this rule
id = "awesome-rule-1"

# Short human-readable description of the rule.
description = "awesome rule 1"

# Golang regular expression used to detect secrets. Note Golang's regex engine
# does not support lookaheads.
regex = '''one-go-style-regex-for-this-rule'''

# Int used to extract secret from regex match and used as the group that will have
# its entropy checked if `entropy` is set.
secretGroup = 3

# Float representing the minimum shannon entropy a regex group must have to be considered a secret.
entropy = 3.5

# Boolean that enables the Token Efficiency filter for this rule. When enabled, candidate secrets
# are evaluated using BPE tokenization (cl100k_base) to measure how "rare" or non-natural-language
# a string is. Common words and phrases tokenize into fewer, longer tokens (high token efficiency),
# while secrets and random strings break into many short tokens (low token efficiency). Strings that
# look like natural language are filtered out as false positives. This is an alternative to entropy
# that is better at distinguishing true secrets from everyday text. (introduced in Betterleaks v1.0.0).
tokenEfficiency = true

# Golang regular expression used to match paths. This can be used as a standalone rule or it can be used
# in conjunction with a valid `regex` entry.
path = '''a-file-path-regex'''

# Keywords are used for pre-regex check filtering. Rules that contain
# keywords will perform a quick string compare check to make sure the
# keyword(s) are in the content being scanned. Ideally these values should
# either be part of the identiifer or unique strings specific to the rule's regex
# (introduced in v8.6.0)
keywords = [
  "auth",
  "password",
  "token",
]

# Array of strings used for metadata and reporting purposes.
tags = ["tag","another tag"]

    # You can define multiple allowlists for a rule to reduce false positives.
    # A finding will be ignored if _ANY_ `[[rules.allowlists]]` matches.
    [[rules.allowlists]]
    description = "ignore commit A"
    # When multiple criteria are defined the default condition is "OR".
    # e.g., this can match on |commits| OR |paths| OR |stopwords|.
    condition = "OR"
    commits = [ "commit-A", "commit-B"]
    paths = [
      '''go\.mod''',
      '''go\.sum'''
    ]
    # note: stopwords targets the extracted secret, not the entire regex match
    # like 'regexes' does. (stopwords introduced in 8.8.0)
    stopwords = [
      '''client''',
      '''endpoint''',
    ]

    [[rules.allowlists]]
    # The "AND" condition can be used to make sure all criteria match.
    # e.g., this matches if |regexes| AND |paths| are satisfied.
    condition = "AND"
    # note: |regexes| defaults to check the _Secret_ in the finding.
    # Acceptable values for |regexTarget| are "secret" (default), "match", and "line".
    regexTarget = "match"
    regexes = [ '''(?i)parseur[il]''' ]
    paths = [ '''package-lock\.json''' ]

# You can extend a particular rule from the default config. e.g., gitlab-pat
# if you have defined a custom token prefix on your GitLab instance
[[rules]]
id = "gitlab-pat"
# all the other attributes from the default rule are inherited

    [[rules.allowlists]]
    regexTarget = "line"
    regexes = [ '''MY-glpat-''' ]


# Global allowlists have a higher order of precedence than rule-specific allowlists.
# If a commit listed in the `commits` field below is encountered then that commit will be skipped and no
# secrets will be detected for said commit. The same logic applies for regexes and paths.
[[allowlists]]
description = "global allow list"
commits = [ "commit-A", "commit-B", "commit-C"]
paths = [
  '''gitleaks\.toml''',
  '''(.*?)(jpg|gif|doc)'''
]
# note: (global) regexTarget defaults to check the _Secret_ in the finding.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"
regexes = [
  '''219-09-9999''',
  '''078-05-1120''',
  '''(9[0-9]{2}|666)-\d{2}-\d{4}''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]

# Common allowlists can be defined once and assigned to multiple rules using |targetRules|.
# This will only run on the specified rules, not globally.
[[allowlists]]
targetRules = ["awesome-rule-1", "awesome-rule-2"]
description = "Our test assets trigger false-positives in a couple rules."
paths = ['''tests/expected/._\.json$''']
```

Refer to the default [betterleaks config](https://github.com/betterleaks/betterleaks/blob/master/config/betterleaks.toml) for examples or follow the [contributing guidelines](https://github.com/betterleaks/betterleaks/blob/master/CONTRIBUTING.md) if you would like to contribute to the default configuration.

### Additional Configuration

#### Composite Rules (Multi-part or `required` Rules)
Betterleaks ships with composite rules, which are made up of a single "primary" rule and one or more auxiliary or `required` rules. To create a composite rule, add a `[[rules.required]]` table to the primary rule specifying an `id` and optionally `withinLines` and/or `withinColumns` proximity constraints. A fragment is a chunk of content that Betterleaks processes at once (typically a file, part of a file, or git diff), and proximity matching instructs the primary rule to only report a finding if the auxiliary `required` rules also find matches within the specified area of the fragment.

**Proximity matching:** Using the `withinLines` and `withinColumns` fields instructs the primary rule to only report a finding if the auxiliary `required` rules also find matches within the specified proximity. You can set:

- **`withinLines: N`** - required findings must be within N lines (vertically)
- **`withinColumns: N`** - required findings must be within N characters (horizontally)
- **Both** - creates a rectangular search area (both constraints must be satisfied)
- **Neither** - fragment-level matching (required findings can be anywhere in the same fragment)

Here are diagrams illustrating each proximity behavior:

```
p = primary captured secret
a = auxiliary (required) captured secret
fragment = section of data gitleaks is looking at


    *Fragment-level proximity*
    Any required finding in the fragment
          ┌────────┐
   ┌──────┤fragment├─────┐
   │      └──────┬─┤     │ ┌───────┐
   │             │a│◀────┼─│✓ MATCH│
   │          ┌─┐└─┘     │ └───────┘
   │┌─┐       │p│        │
   ││a│    ┌─┐└─┘        │ ┌───────┐
   │└─┘    │a│◀──────────┼─│✓ MATCH│
   └─▲─────┴─┴───────────┘ └───────┘
     │    ┌───────┐
     └────│✓ MATCH│
          └───────┘


   *Column bounded proximity*
   `withinColumns = 3`
          ┌────────┐
   ┌────┬─┤fragment├─┬───┐
   │      └──────┬─┤     │ ┌───────────┐
   │    │        │a│◀┼───┼─│+1C ✓ MATCH│
   │          ┌─┐└─┘     │ └───────────┘
   │┌─┐ │     │p│    │   │
┌──▶│a│  ┌─┐  └─┘        │ ┌───────────┐
│  │└─┘ ││a│◀────────┼───┼─│-2C ✓ MATCH│
│  │       ┘             │ └───────────┘
│  └── -3C ───0C─── +3C ─┘
│  ┌─────────┐
│  │ -4C ✗ NO│
└──│  MATCH  │
   └─────────┘


   *Line bounded proximity*
   `withinLines = 4`
         ┌────────┐
   ┌─────┤fragment├─────┐
  +4L─ ─ ┴────────┘─ ─ ─│
   │                    │
   │              ┌─┐   │ ┌────────────┐
   │         ┌─┐  │a│◀──┼─│+1L ✓ MATCH │
   0L  ┌─┐   │p│  └─┘   │ ├────────────┤
   │   │a│◀──┴─┴────────┼─│-1L ✓ MATCH │
   │   └─┘              │ └────────────┘
   │                    │ ┌─────────┐
  -4L─ ─ ─ ─ ─ ─ ─ ─┌─┐─│ │-5L ✗ NO │
   │                │a│◀┼─│  MATCH  │
   └────────────────┴─┴─┘ └─────────┘


   *Line and column bounded proximity*
   `withinLines = 4`
   `withinColumns = 3`
         ┌────────┐
   ┌─────┤fragment├─────┐
  +4L   ┌└────────┴ ┐   │
   │            ┌─┐     │ ┌───────────────┐
   │    │       │a│◀┼───┼─│+2L/+1C ✓ MATCH│
   │         ┌─┐└─┘     │ └───────────────┘
   0L   │    │p│    │   │
   │         └─┘        │
   │    │           │   │ ┌────────────┐
  -4L    ─ ─ ─ ─ ─ ─┌─┐ │ │-5L/+3C ✗ NO│
   │                │a│◀┼─│   MATCH    │
   └───-3C────0L───+3C┴─┘ └────────────┘
```


#### betterleaks:allow / gitleaks:allow

If you are knowingly committing a test secret that betterleaks will catch you can add a `betterleaks:allow` (or `gitleaks:allow` for backwards compatibility) comment to that line which will instruct betterleaks
to ignore that secret. Ex:

```
class CustomClass:
    discord_client_secret = '8dyfuiRyq=vVc3RRr_edRk-fK__JItpZ'  #betterleaks:allow

```

#### .betterleaksignore / .gitleaksignore

You can ignore specific findings by creating a `.betterleaksignore` (or `.gitleaksignore` for backwards compatibility) file at the root of your repo. In release v8.10.0 a `Fingerprint` value was added to the report. Each leak, or finding, has a Fingerprint that uniquely identifies a secret. Add this fingerprint to the ignore file to ignore that specific secret. See the [.gitleaksignore](https://github.com/betterleaks/betterleaks/blob/master/.betterleaksignore) for an example. Note: this feature is experimental and is subject to change in the future.

#### Decoding

Sometimes secrets are encoded in a way that can make them difficult to find
with just regex. Now you can tell gitleaks to automatically find and decode
encoded text. The flag `--max-decode-depth` tweaks this feature (the default
value "5").

Recursive decoding is supported since decoded text can also contain encoded
text.  The flag `--max-decode-depth` sets the recursion limit. Recursion stops
when there are no new segments of encoded text to decode, so setting a really
high max depth doesn't mean it will make that many passes. It will only make as
many as it needs to decode the text. Overall, decoding only minimally increases
scan times.

The findings for encoded text differ from normal findings in the following
ways:

- The location points the bounds of the encoded text
  - If the rule matches outside the encoded text, the bounds are adjusted to
    include that as well
- The match and secret contain the decoded value
- Two tags are added `decoded:<encoding>` and `decode-depth:<depth>`

Currently supported encodings:

- **percent** - Any printable ASCII percent encoded values
- **hex** - Any printable ASCII hex encoded values >= 32 characters
- **base64** - Any printable ASCII base64 encoded values >= 16 characters
- **unicode** - Unicode escape sequences (`U+XXXX`, `\uXXXX`, `\\uXXXX`) decoded to UTF-8

#### Archive Scanning

Sometimes secrets are packaged within archive files like zip files or tarballs,
making them difficult to discover. Now you can tell gitleaks to automatically
extract and scan the contents of archives. The flag `--max-archive-depth`
enables this feature for both `dir` and `git` scan types. The default value of
"0" means this feature is disabled by default.

Recursive scanning is supported since archives can also contain other archives.
The `--max-archive-depth` flag sets the recursion limit. Recursion stops when
there are no new archives to extract, so setting a very high max depth just
sets the potential to go that deep. It will only go as deep as it needs to.

The findings for secrets located within an archive will include the path to the
file inside the archive. Inner paths are separated with `!`.

Example finding (shortened for brevity):

```
Finding:     DB_PASSWORD=8ae31cacf141669ddfb5da
...
File:        testdata/archives/nested.tar.gz!archives/files.tar!files/.env.prod
Line:        4
Commit:      6e6ee6596d337bb656496425fb98644eb62b4a82
...
Fingerprint: 6e6ee6596d337bb656496425fb98644eb62b4a82:testdata/archives/nested.tar.gz!archives/files.tar!files/.env.prod:generic-api-key:4
Link:        https://github.com/leaktk/gitleaks/blob/6e6ee6596d337bb656496425fb98644eb62b4a82/testdata/archives/nested.tar.gz
```

This means a secret was detected on line 4 of `files/.env.prod.` which is in
`archives/files.tar` which is in `testdata/archives/nested.tar.gz`.

Currently supported formats:

The [compression](https://github.com/mholt/archives?tab=readme-ov-file#supported-compression-formats)
and [archive](https://github.com/mholt/archives?tab=readme-ov-file#supported-archive-formats)
formats supported by mholt's [archives package](https://github.com/mholt/archives)
are supported.

#### Reporting

Betterleaks has built-in support for several report formats: [`json`](https://github.com/betterleaks/betterleaks/blob/master/testdata/expected/report/json_simple.json), [`csv`](https://github.com/betterleaks/betterleaks/blob/master/testdata/expected/report/csv_simple.csv?plain=1), [`junit`](https://github.com/betterleaks/betterleaks/blob/master/testdata/expected/report/junit_simple.xml), and [`sarif`](https://github.com/betterleaks/betterleaks/blob/master/testdata/expected/report/sarif_simple.sarif).

If none of these formats fit your need, you can create your own report format with a [Go `text/template` .tmpl file](https://www.digitalocean.com/community/tutorials/how-to-use-templates-in-go#step-4-writing-a-template) and the `--report-template` flag. The template can use [extended functionality from the `Masterminds/sprig` template library](https://masterminds.github.io/sprig/).

For example, the following template provides a custom JSON output:
```gotemplate
# jsonextra.tmpl
[{{ $lastFinding := (sub (len . ) 1) }}
{{- range $i, $finding := . }}{{with $finding}}
    {
        "Description": {{ quote .Description }},
        "StartLine": {{ .StartLine }},
        "EndLine": {{ .EndLine }},
        "StartColumn": {{ .StartColumn }},
        "EndColumn": {{ .EndColumn }},
        "Line": {{ quote .Line }},
        "Match": {{ quote .Match }},
        "Secret": {{ quote .Secret }},
        "File": "{{ .File }}",
        "SymlinkFile": {{ quote .SymlinkFile }},
        "Commit": {{ quote .Commit }},
        "Entropy": {{ .Entropy }},
        "Author": {{ quote .Author }},
        "Email": {{ quote .Email }},
        "Date": {{ quote .Date }},
        "Message": {{ quote .Message }},
        "Tags": [{{ $lastTag := (sub (len .Tags ) 1) }}{{ range $j, $tag := .Tags }}{{ quote . }}{{ if ne $j $lastTag }},{{ end }}{{ end }}],
        "RuleID": {{ quote .RuleID }},
        "Fingerprint": {{ quote .Fingerprint }}
    }{{ if ne $i $lastFinding }},{{ end }}
{{- end}}{{ end }}
]
```

Usage:
```sh
$ betterleaks dir ~/leaky-repo/ --report-path "report.json" --report-format template --report-template testdata/report/jsonextra.tmpl
```

## Exit Codes

You can always set the exit code when leaks are encountered with the --exit-code flag. Default exit codes below:

```
0 - no leaks present
1 - leaks or error encountered
126 - unknown flag
```
