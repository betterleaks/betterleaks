# Betterleaks config

The `betterleaks.toml` file controls detection, filtering, and validation.
It is TOML because rules are mostly flat data plus Expr expressions.

## Top-level shape

Every config can use these fields:

- `prefilter`: global Expr expression that skips entire files, commits, or other source fragments before regex matching.
- `filter`: global Expr expression that discards specific findings after regex matching.
- `betterleaksMinVersion`: minimum Betterleaks binary version required.
- `minVersion`: minimum Gitleaks config format version required for compatibility.
- `[extend]`: inherit rules/settings from another config or from built-in defaults.
- `[[rules]]`: secret detection rules.

Each `[[rules]]` entry can use:

- `id`: unique rule identifier.
- `description`: human-readable description.
- `keywords`: strings used for fast pre-regex filtering.
- `regex`: regular expression used to detect the secret.
- `filter`: rule-specific Expr expression to discard false positives.
- `confidence`: optional `low`, `medium`, or `high` likelihood classification.
- `validate`: Expr expression to actively verify whether a secret is live.
- `components`: required or optional component rules used to build multipart findings.

`keywords` are strongly recommended. Betterleaks checks them with an
Aho-Corasick trie before running the heavier regex.

## Expr overview

Betterleaks uses [Expr](https://expr-lang.org/) for `prefilter`, `filter`, and
`validate` expressions.

- `prefilter` runs before regex matching and only has `attributes`.
- `filter` runs after regex matching and has `attributes` and `finding`.
- `validate` runs after filtering when validation is enabled and has
  `attributes`, `finding`, and `components`.

Use brackets to access map values. For nested data that may be absent, use `?.`
and provide a fallback with `??`:

```expr
attributes["path"]
components["account-id"]?.secret ?? ""
r.json?.login ?? ""
```

## Data available to Expr

| Name | Scope | Description |
| :--- | :--- | :--- |
| `attributes` | prefilter, filter, validate | Source metadata. Common keys include `path`, `git.sha`, `git.author_name`, `git.author_email`, `git.date`, `git.message`, `git.remote_url`, `git.platform`, `fs.symlink`, and the read-only `fs.first_fragment` (`"true"` for a file's first chunk and `"false"` thereafter). |
| `finding` | filter, validate | Matched secret data. Common keys include `secret`, `match`, `line`, `rule_id`, and `description`. In validation, `finding["captures"]` contains the primary rule's named regex groups. |
| `components` | validate | Matched component findings, keyed by the referenced component rule ID. Each has `secret` and `captures` fields. |

The full attributes source is maintained in
[`sources/attribute.go`](https://github.com/betterleaks/betterleaks/blob/main/sources/attribute.go).

Filter expressions also receive `finding["fragment_raw"]` and the byte offsets
`match_start_idx`, `match_end_idx`, `match_line_start_idx`, and
`match_line_end_idx`. These can be combined with Expr string slicing:

```expr
let providerMatchContext = finding["fragment_raw"][
    max(finding["match_start_idx"] - 150, finding["match_line_start_idx"]):
    min(finding["match_end_idx"] + 50, finding["match_line_end_idx"])
];
filter.containsAny(providerMatchContext, ["provider"])
```

Regex extraction can further restrict a context window. This example recreates
a `[\w.-]{0,50}` regex preamble by retaining only the contiguous word, dot, and
hyphen suffix immediately before the match:

```expr
let genericMatchPrefix = filter.findMatch(
    finding["fragment_raw"][
        max(finding["match_start_idx"] - 50, finding["match_line_start_idx"]):
        finding["match_start_idx"]
    ],
    `[\w.-]{0,50}$`
);
let genericMatchContext =
    genericMatchPrefix +
    finding["fragment_raw"][finding["match_start_idx"]:finding["match_end_idx"]];
```

## Filtering

Filters are the configuration mechanism for suppressing false positives. If a
filter expression evaluates to `true`, the item is skipped.

### Filter functions

| Function | Description |
| :--- | :--- |
| `filter.matchesAny(string, list)` | Returns `true` if the string matches any regex pattern in the list. |
| `matchesAny(string, list)` | Equivalent to `filter.matchesAny(string, list)`. |
| `filter.findMatch(string, pattern)` | Returns the first substring matching the regex pattern, or an empty string if there is no match. |
| `filter.containsAny(string, list)` | Returns `true` if the string contains any listed term. Uses an efficient Aho-Corasick substring match. |
| `containsAny(string, list)` | Equivalent to `filter.containsAny(string, list)`. |
| `filter.entropy(string)` | Returns Shannon entropy as a float. Useful for filtering non-random placeholders. |
| `entropy(string)` | Equivalent to `filter.entropy(string)`; useful for concise rule filters. |
| `filter.tokenRatio(string)` | Returns the string's byte length divided by its token count. Higher values are more tokenizer-compressible and therefore more likely to be readable text. |
| `filter.failsTokenEfficiency(string)` | Returns `true` when the generic-secret heuristic identifies readable text using token ratio, wordlist matches, and a length-sensitive threshold. |
| `filter.setConfidence(level)` | Sets the current finding's `confidence` attribute. Use as `let _ = filter.setConfidence(level);`. |

Use `filter.tokenRatio` when a rule needs an explicit threshold without the
generic heuristic's wordlist check. For example, this skips low-entropy or
readable-looking candidates:

```expr
filter.entropy(finding["secret"]) < 3.0 ||
filter.tokenRatio(finding["secret"]) >= 2.5
```

Example:

```toml
filter = '''
(
    filter.matchesAny(attributes["git.author_name"], [`\[bot\]$`]) &&
    filter.matchesAny(attributes["path"], [`^tests/fixtures/`]) &&
    filter.containsAny(finding["secret"], ["_MOCK_", "_TEST_"])
)
||
(
    filter.matchesAny(attributes["path"], [`(?i)\.(?:md|txt|csv)$`]) &&
    (
        filter.containsAny(finding["line"], ["Example:", "Placeholder:", "Replace this with"]) ||
        finding["secret"] == "SUPER_SECRET_EXAMPLE_KEY_12345"
    )
)
||
(
    filter.entropy(finding["secret"]) <= 2.5 &&
    filter.failsTokenEfficiency(finding["secret"])
)
'''
```

Rules may set a default confidence and broad rules may refine it in their
filter:

```toml
[[rules]]
id = "generic-api-key"
confidence = "low"
filter = '''
let level = filter.matchesAny(finding["line"], [`(?i)\b[a-z0-9]+[_.-]+token\b`]) ? "medium" : "low";
let _ = filter.setConfidence(level);
false
'''
```

`--confidence low|medium|high` keeps findings at or above that level. Findings
without a recognized confidence attribute remain included.

## Validation

Validation verifies whether a detected secret is live by evaluating the rule's
`validate` Expr expression. By default, validation is disabled. Enable it with
the `--validation` flag.

Validation runs asynchronously, and responses are cached in memory so duplicate
secrets only trigger one network request.

To revalidate one known credential without scanning or re-running a rule's
detection regex, use `betterleaks validate --rule-id <rule-id>`. See the
[`validate` command guide](scanning.md#validate) for stdin, multipart
credentials, captures, request controls, and reporting.

### Request limits

Live validation can send many authentication requests when a scan finds
different candidate credentials for the same provider. The following flags
limit the actual outbound requests made by generic HTTP validators and the
built-in AWS, GCP, and Azure validators:

| Flag | Description |
| :--- | :--- |
| `--validation-max-requests N` | Sends at most `N` requests to each provider target origin during the scan. `0` means unlimited. The singular `--validation-max-request` spelling is accepted as an alias. |
| `--validation-rps N` | Limits all validation requests to `N` requests per second. Fractional values are accepted; `0` means unlimited. |
| `--validation-rps-rule RULE=N` | Limits one exact rule ID to `N` requests per second. Repeat the flag for additional rules. |

The global and rule-specific rates compose: a request must satisfy both limits.
Rate limits use strict spacing with no initial burst. A provider target is an
HTTP origin such as `https://api.github.com`; multiple rules that use the same
origin share its maximum-request budget. Redirects and multi-request validation
expressions count each actual outbound request. Validation cache hits do not
count. Time spent waiting for an RPS slot does not consume
`--validation-timeout`; that timeout begins when the provider request starts and
remains active while its response body is read. Redirect hops share that one
provider-time budget, while each hop still counts as an outbound request for RPS
and maximum-request enforcement.

For example:

```sh
betterleaks dir . --validation \
  --validation-max-requests 1000 \
  --validation-rps 10 \
  --validation-rps-rule github-pat=2 \
  --validation-rps-rule github-fine-grained-pat=2
```

Once a provider target reaches `--validation-max-requests`, further validations
that need to call it return `needs_validation` without sending the request. The
finding includes `betterleaks_max_requests_hit`,
`betterleaks_validation_target`, `betterleaks_validation_max_requests`, and
`betterleaks_validation_requests_sent` metadata.

### Result format

A validation expression must return a map with a `"result"` key. Supported
statuses are:

- `"valid"`
- `"needs_validation"`
- `"invalid"`
- `"revoked"`
- `"unknown"`
- `"error"`

Any additional keys are attached to the finding as validation metadata, such as
`username`, `email`, `scopes`, or `reason`.

### Validation functions

| Function | Description |
| :--- | :--- |
| `http.get(url, headers)` | Sends a GET request. |
| `http.post(url, headers, body)` | Sends a POST request. |
| `validate.unknown(response)` | Returns `{"result": "unknown", "reason": "HTTP <status>"}` for unexpected HTTP responses. |
| `env.get(name)` | Reads an allowlisted environment variable. Requires `--validation-env-vars`. |
| `env.getOrDefault(name, default)` | Reads an allowlisted environment variable, or returns `default` when env access is disabled, the name is not allowlisted, or the variable is unset. |
| `strings.obfuscate(secret)` | Returns a same-length, shape-preserving stand-in for a secret. Useful before sending context to third-party APIs. |
| `json.string(value)` | Returns a quoted JSON string literal. Useful when hand-building JSON request bodies. |
| `strings.urlQueryEscape(value)` | URL-query escapes a string. Useful when building signed validation request URLs. |
| `crypto.md5(bytes)` | Returns the MD5 hash as bytes. |
| `crypto.sha1(bytes)` | Returns the SHA-1 hash as bytes. |
| `crypto.hmacSha1(key, msg)` | Returns the HMAC-SHA1 signature as bytes. |
| `crypto.hmacSha256(key, msg)` | Returns the HMAC-SHA256 signature as bytes. |
| `hex.encode(bytes)` | Returns lowercase hex encoding. |
| `time.nowUnix()` | Returns the current Unix timestamp as a string. |
| `time.nowRFC3339()` | Returns the current UTC timestamp in RFC3339 format. |
| `aws.validate(key, secret)` | Makes a SigV4-signed AWS STS request to validate AWS credentials. |
| `gcp.validate(json)` | Exchanges GCP service-account or ADC JSON for an OAuth token and returns validation metadata. |
| `azure.validateStorage(account, key)` | Makes a SharedKey-signed Azure Storage request to validate an account key. |
| `azure.validateServicePrincipal(tenant, client, secret)` | Requests a Microsoft identity token to validate an Azure service principal secret. |
| `azure.validateAppConfig(endpoint, id, secret)` | Makes an HMAC-signed Azure App Configuration request to validate a connection string. |
| `azure.validateServiceBusSAS(connectionString)` | Makes a SAS-authenticated Azure Service Bus/Event Hub request to validate a connection string. |
| `base64.encode(bytes)` / `base64.decode(string)` | Encodes or decodes standard base64. |
| `let name = value; expr` | Binds a variable to avoid repeating sub-expressions. |

`http.get` and `http.post` return a response map:

| Field | Description |
| :--- | :--- |
| `r.status` | HTTP status code as an integer. |
| `r.body` | Raw response body as a string. |
| `r.json` | Parsed JSON body as a dynamic object. Empty object if the body is not JSON. |
| `r.headers` | Response headers with lowercased keys. |

Example:

```toml
validate = '''
let r = http.get("https://api.github.com/app", {
    "Accept": "application/vnd.github+json",
    "Authorization": "Bearer " + finding["secret"]
  });
r.status == 200 && (r.json?.slug ?? "") != "" ? {
    "result": "valid",
    "slug": r.json?.slug ?? "",
    "name": r.json?.name ?? "",
    "html_url": r.json?.html_url ?? "",
    "external_url": r.json?.external_url ?? ""
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
'''
```

For more complex validation setups, such as Basic Auth, dynamic request bodies,
HMAC signatures, or composite rules, check the built-in
rules in `cmd/generate/config/rules`.

## Components

A rule can reference other rules as required or optional components. The
top-level rule regex remains the reported secret and proximity anchor:

```toml
[[rules]]
id = "credential"
regex = '''credential[=: ]+([A-Za-z0-9_-]+)'''
components = [
  { id = "account-id", within = "5L" },
  { id = "session-token", optional = true, within = "-2L,+4C" },
]
```

Components are required by default. Set `optional = true` to attach a component
when present without making it gate the primary finding; `optional = false` is
equivalent to omitting the field. `within` is optional and uses the same grammar
as `--match-context`: `5L` allows the primary match line plus up to four lines
before and after, `100C` allows 100 characters on either side, and signs make a
boundary directional (for example, `-2L,+4C`). When `within` is omitted, the
component only needs to occur in the same fragment.

Validation receives primary captures and matched components in this canonical
shape:

```expr
finding["captures"]                         // primary rule named capture groups
components["account-id"]?.secret            // component's selected secret
components["account-id"]?.captures?.id       // component named capture group
```

Use `?.` when a component or nested field may be absent, and `??` to select a
fallback. An optional component that is not found has no entry in `components`:

```expr
let account = components["account-id"]?.secret ?? "";
let session = components["session-token"]?.secret ?? "";
let region = components["account-id"]?.captures?.region ?? "";
```

The older `[[rules.required]]` syntax is deprecated and treated as required
components when `components` is absent. Its `withinLines` and `withinColumns`
fields are translated to `within`. If both forms are present on a rule,
`components` takes precedence. Config display and generated configs emit only
the new field.

### Overriding rule defaults with env vars

`env.getOrDefault` lets a rule treat any hardcoded value - an API host, a
region, an account ID - as a default that the user can override at scan time.
The rule reads an allowlisted variable and falls back to the literal default
when env access is disabled, the name is not allowlisted, or the variable is
unset:

```expr
let base_url = env.getOrDefault("SOME_BASE_URL", "https://default.example.com");
let r = http.get(base_url + "/whoami", { ... });
...
```

To override the default, the variable must be passed via
`--validation-env-vars`. Unlike `env.get`, missing allowlist configuration does
not produce a validation error for `env.getOrDefault`; it just returns the
provided default. If the variable is allowlisted and explicitly set to an empty
string, `env.getOrDefault` returns `""`.

The built-in `github-*` rules use `env.getOrDefault` with `GITHUB_BASE_URL` so
the same rules validate against GitHub Enterprise Server:

```sh
export GITHUB_BASE_URL=https://github.example.com/api/v3
betterleaks github --validation --validation-env-vars GITHUB_BASE_URL https://github.example.com/owner
```

Use `env.get` instead when the env var is required for the validator to be
meaningful, such as provider API keys used only for validation. `env.get`
returns an Expr error when env access is disabled or the name is not allowlisted.

## Validation with an LLM

For generic high-entropy matches that no live API can adjudicate, a validation
expression can ask an LLM whether the candidate looks like a real secret. Use
`json.string(...)` for quoted/escaped prompt fragments, `env.get(...)` plus
`--validation-env-vars` for provider API keys, and `strings.obfuscate(...)`
when you want to avoid sending the raw candidate to a third-party API.

Treat positive model output as `"needs_validation"` unless the credential was
authoritatively verified through a live service.

```toml
[[rules]]
id = "generic-secret-llm-filtered"
description = "Generic secret filtered by an LLM"
regex = '''(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:\\?['"\x60]|[\s;]|\\[nr]|$)'''
keywords = ["access", "api", "auth", "key", "credential", "creds", "password", "secret", "token"]

filter = '''
filter.entropy(finding["secret"]) <= 4.0 ||
filter.failsTokenEfficiency(finding["secret"])
'''

validate = '''
let obf_secret = strings.obfuscate(finding["secret"]);
let obf_context = replace(finding["context"], finding["secret"], obf_secret);
let r = http.post(
  "https://api.openai.com/v1/chat/completions",
  {
    "Authorization": "Bearer " + env.get("OPENAI_API_KEY"),
    "Content-Type": "application/json"
  },
  "{" +
    "\"model\":\"gpt-5.4-mini\"," +
    "\"temperature\":0," +
    "\"max_completion_tokens\":256," +
    "\"messages\":[" +
      "{\"role\":\"system\",\"content\":" +
        json.string(
          "Classify whether the candidate is a real usable credential or a benign match. " +
          "Respond with exactly three lines: VERDICT_SECRET or VERDICT_NOT, confidence from 0.0 to 1.0, and a short justification."
        ) +
      "}," +
      "{\"role\":\"user\",\"content\":" +
        json.string("Candidate: " + obf_secret + "\n\nSurrounding code:\n" + obf_context) +
      "}" +
    "]" +
  "}"
);
let content = r.json?.choices?.[0]?.message?.content ?? "";
r.status == 200 && r.body contains "VERDICT_SECRET" ? {
  "result": "needs_validation",
  "justification": content
} : r.status == 200 && r.body contains "VERDICT_NOT" ? {
  "result": "invalid",
  "justification": content
} : validate.unknown(r)
'''
```

## Expr function naming

Project-owned Expr functions use short lower-case namespaces with camelCase
function names. Examples: `http.get`, `crypto.hmacSha256`,
`filter.matchesAny`, `env.getOrDefault`, and `validate.unknown`.

Project-owned data keys stay snake_case. This includes attribute keys, finding
keys, and response map keys such as `error_code`. Capture names and component
rule IDs are user-defined and are preserved exactly as map keys.

## Adding an Expr binding

For contributors adding a new Expr function:

1. Choose the environment: validation, filter/prefilter, or both.
2. Add the Go implementation in the namespace file, or create
   `internal/exprruntime/bindings_<namespace>.go` for a new namespace.
3. Register the function in `baseEnv`.
4. Add focused tests for compile and evaluation behavior.
5. Run `go test ./internal/exprruntime`.
