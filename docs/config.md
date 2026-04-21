### The Betterleaks Format
The `betterleaks.toml` file is how betterleaks determines detection, filtering, and validation behaviors.
It's written in the TOML format. For two reasons; 1. it's not YAML, and 2. rules are best expressed as flat data.

Every Betterleaks config has the following sections and fields available, though not all are required:
- `prefilter` - Global CEL expression to skip entire files or commits.
- `filter` - Global CEL expression to discard specific findings across all rules.
- `betterleaksMinVersion` - Minimum Betterleaks binary version required.
- `minVersion` - Minimum Gitleaks config format version required (for backwards compatibility).
- `[extend]` - Inherit rules and settings from another config or the built-in defaults.
    - `useDefault` - Boolean flag to inherit built-in rules.
- `[[rules]]` - An array of tables defining specific secret detection rules.
    - `id` - Unique string identifier.
    - `description` - Human-readable description.
    - `keywords` - Array of strings for fast pre-regex filtering.
    - `regex` - Regular expression used to detect the secret.
    - `filter` - Rule-specific CEL expression to discard false positives.
    - `validate` - CEL expression to actively verify if a secret is live.
    - `[[rules.required]]` - Defines composite/multi-part rules.
        - `id` - The ID of the required auxiliary rule.
        - `withinLines` - The required finding must be within this many lines vertically.
        - `withinColumn` - The required finding must be within this many characters horizontally.
---

## The `[[rules]]` table
The `[[rules]]` table is the core of Betterleaks. Each entry instructs the engine on exactly what a secret looks like.
To ensure scans are lightning-fast, you should always include `keywords`. Betterleaks uses an Aho-Corasick trie to check for these strings *before* executing the heavier `regex`.

You can also define **Composite Rules** using `[[rules.required]]`. This allows you to say, "This primary rule is only valid if we also find these auxiliary rules nearby." Note that `[[rules.required]]` will be replaced with `components` in a later release.

## Betterleaks `filter`s
Filters replace legacy allowlists, entropy checks, and token efficiency checks with dynamic Common Expression Language (CEL) statements. If a filter expression evaluates to `true`, the item is **skipped/discarded**.

* **`prefilter`**: Exists only at the global level. It evaluates *before* any regex runs and only has access to file/commit metadata (`attributes`). Use this to entirely bypass binary files or bot commits.
* **`filter`**: Exists globally and per-rule. It evaluates *after* a regex match is found and has access to both `attributes` and the `finding` itself.

Note that safe attribute access requires somewhat cumbersome syntax, `attributes.[?"key"].orValue("")`. If `key` does not exist in the attributes map, then it will default to using an empty string, `""`.

### Available `filter` bindings

| Binding / Function | Description |
| :--- | :--- |
| `attributes` | A map of metadata. Keys include: `path`, `git.sha`, `git.author_name`, `git.author_email`, `git.date`, `git.message`, `git.remote_url`, `git.platform`, `fs.symlink`. Full list of available keys [available here](https://github.com/betterleaks/betterleaks/blob/main/sources/attribute.go). |
| `finding` | A map representing the secret. Keys include: `secret` (the extracted value), `match` (the full regex match), `line` (the line of code), `rule_id`, and `description`. |
| `matchesAny(string, list)` | Returns `true` if the string matches any of the provided regex patterns. |
| `containsAny(string, list)` | Returns `true` if the string contains any of the provided strings (uses an efficient Aho-Corasick substring match). |
| `entropy(string)` | Returns the Shannon entropy (float) of the string. Useful for filtering out non-random placeholders. |
| `failsTokenEfficiency(string)`| Returns `true` if the string tokenizes too efficiently (i.e., it looks like natural language instead of a random secret). |
---

Example `filter` CEL expression:

```toml
filter = '''
(
    // Ignore if authored by a bot AND inside the fixtures folder AND the secret contains a known test string.
    attributes[?"git.author_name"].orValue("").endsWith("[bot]") &&
    attributes[?"path"].orValue("").startsWith("tests/fixtures/") &&
    containsAny(finding["secret"], ["_MOCK_", "_TEST_"])
)
||
(
    // Ignore if it's a Markdown or text file AND the specific line of code contains instructional text.
    matchesAny(attributes[?"path"].orValue(""), [r"""(?i)\.(?:md|txt|csv)$"""]) &&
    (
        containsAny(finding["line"], ["Example:", "Placeholder:", "Replace this with"]) ||
        finding["secret"] == "SUPER_SECRET_EXAMPLE_KEY_12345"
    )
)
||
(
    // Ignore if the entropy is low AND it tokenizes like natural language instead of a random string.
    entropy(finding["secret"]) <= 2.5 &&
    failsTokenEfficiency(finding["secret"])
)
'''


```

## Betterleaks `validate`
Validation allows Betterleaks to automatically verify if a detected secret is active by making asynchronous HTTP requests directly from the rule definition.

Your CEL expression must return a map containing a `"result"` key. The valid statuses are `"valid"`, `"invalid"`, `"revoked"`, `"unknown"`, and `"error"`. Any additional keys returned in the map are attached to the finding as extra metadata (e.g., `username`, `email`, `scopes`).

### Available `validate` bindings

| Binding / Function | Description |
| :--- | :--- |
| `secret` | A string containing the extracted secret value. |
| `captures` | A map containing any named capture groups defined in your rule's regex. |
| `http.get(url, headers)` | Fires a GET request. Returns a response map `r` with `r.status` (int), `r.json` (dynamic object), `r.body` (string), and `r.headers` (map). |
| `http.post(url, headers, body)`| Fires a POST request and returns the same response map `r` as `http.get`. |
| `cel.bind(name, value, expr)` | Binds a variable to avoid repeating sub-expressions (e.g., binding the HTTP response to `r`). |
| `unknown(response)` | A helper function that takes an HTTP response map and returns `{"result": "unknown", "reason": "HTTP <status>"}`. |
| `md5(string)` | Returns the MD5 hash of the string. |
| `crypto.hmac_sha256(key, msg)` | Returns the HMAC-SHA256 signature (as bytes). |
| `time.now_unix()` | Returns the current Unix timestamp as a string. |
| `aws.validate(key, secret)` | A specialized helper that makes a SigV4-signed request to the AWS STS API to validate AWS keys. |

Example validate CEL expression:
```toml
validate = '''
cel.bind(r,
  http.get("https://api.github.com/app", {
    "Accept": "application/vnd.github+json",
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.json.?slug.orValue("") != "" ? {
    "result": "valid",
    "slug": r.json.?slug.orValue(""),
    "name": r.json.?name.orValue(""),
    "html_url": r.json.?html_url.orValue(""),
	"external_url": r.json.?external_url.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)
'''
```
This reads as "set r as the response to an http GET call from api.github.com/app, then if status is 200 and `slug` is in the return json, *then* return 'result' valid otherwise if status is 401 or 403, return 'invalid', and finally if none of the conditions are met, return 'unknown'".
