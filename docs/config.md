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
- `validate`: Expr expression to actively verify whether a secret is live.
- `[[rules.required]]`: composite rule requirements.

`keywords` are strongly recommended. Betterleaks checks them with an
Aho-Corasick trie before running the heavier regex.

## Expr overview

Betterleaks uses [Expr](https://expr-lang.org/) for `prefilter`, `filter`, and
`validate` expressions. Existing CEL-shaped expressions are still accepted for
compatibility, but new configs should use Expr syntax.

- `prefilter` runs before regex matching and only has `attributes`.
- `filter` runs after regex matching and has `attributes` and `finding`.
- `validate` runs after filtering when validation is enabled and has
  `attributes`, `finding`, and `captures`.

Safe map access uses `get`, and optional object access uses `?.` plus `??`:

```expr
get(attributes, "path", "")
r.json?.login ?? ""
```

## Data available to Expr

| Name | Scope | Description |
| :--- | :--- | :--- |
| `attributes` | prefilter, filter, validate | Source metadata. Common keys include `path`, `git.sha`, `git.author_name`, `git.author_email`, `git.date`, `git.message`, `git.remote_url`, `git.platform`, and `fs.symlink`. |
| `finding` | filter, validate | Matched secret data. Common keys include `secret`, `match`, `line`, `rule_id`, and `description`. |
| `captures` | validate | Named capture groups from the rule regex. |

The full attributes source is maintained in
[`sources/attribute.go`](https://github.com/betterleaks/betterleaks/blob/main/sources/attribute.go).

## Filtering

Filters replace legacy allowlists, entropy checks, and token efficiency checks
with Expr. If a filter expression evaluates to `true`, the item is skipped.

### Filter functions

| Function | Description |
| :--- | :--- |
| `filter.matchesAny(string, list)` | Returns `true` if the string matches any regex pattern in the list. |
| `filter.containsAny(string, list)` | Returns `true` if the string contains any listed term. Uses an efficient Aho-Corasick substring match. |
| `filter.entropy(string)` | Returns Shannon entropy as a float. Useful for filtering non-random placeholders. |
| `filter.failsTokenEfficiency(string)` | Returns `true` if the string tokenizes too efficiently and looks like natural language rather than a random secret. |

Example:

```toml
filter = '''
(
    filter.matchesAny(get(attributes, "git.author_name", ""), [`\[bot\]$`]) &&
    filter.matchesAny(get(attributes, "path", ""), [`^tests/fixtures/`]) &&
    filter.containsAny(finding["secret"], ["_MOCK_", "_TEST_"])
)
||
(
    filter.matchesAny(get(attributes, "path", ""), [`(?i)\.(?:md|txt|csv)$`]) &&
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

## Validation

Validation verifies whether a detected secret is live by evaluating the rule's
`validate` Expr expression. By default, validation is disabled. Enable it with
the `--validation` flag.

Validation runs asynchronously, and responses are cached in memory so duplicate
secrets only trigger one network request.

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
HMAC signatures, or composite `[[rules.required]]` rules, check the built-in
rules in `cmd/generate/config/rules`.

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
let content = getPath(r.json, "choices.0.message.content", "");
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

Data keys stay snake_case. This includes capture keys, attribute keys, finding
keys, and response map keys such as `error_code`.

## Adding an Expr binding

For contributors adding a new Expr function:

1. Choose the environment: validation, filter/prefilter, or both.
2. Add the Go implementation in the namespace file, or create
   `internal/exprruntime/bindings_<namespace>.go` for a new namespace.
3. Register the function in `baseEnv`.
4. Add focused tests for compile and evaluation behavior.
5. Run `go test ./internal/exprruntime`.
