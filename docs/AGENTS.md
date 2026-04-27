# Writing Rules for betterleaks

This guide covers the three CEL environments available when writing rules: **prefilter**, **filter**, and **validate**. Each has a different scope, different variables in scope, and a different purpose.

---

## Overview

```
source fragment
      │
      ▼
 ┌─────────────┐
 │  prefilter  │  ← runs before regex; attributes only
 └──────┬──────┘
        │ (not skipped)
        ▼
  regex + keywords
        │ (match found)
        ▼
 ┌─────────────┐
 │   filter    │  ← runs per match; attributes + finding
 └──────┬──────┘
        │ (not discarded)
        ▼
 ┌─────────────┐
 │  validate   │  ← optional; fires network requests to validate liveness
 └─────────────┘
```

A `prefilter` or `filter` expression that evaluates to **`true` means skip/discard** the item. A `validate` expression returns a result map.

---

## `prefilter` — Fragment-level filtering

`prefilter` exists **only at the global config level**. It runs before any regex is applied, so it's the cheapest place to reject entire files or commits. Only `attributes` is in scope — `finding` is not available yet.

### Variables

| Variable | Type | Description |
|---|---|---|
| `attributes` | `map<string, string>` | Metadata about the source fragment being scanned. See [Attribute Keys](#attribute-keys) below. |

### Examples of when to use prefilter

- Skip binary, generated, or vendored files by path
- Skip commits from known bot accounts
- Skip entire directories that are high-noise and low-value

### Example

```toml
# In betterleaks.toml (global level only)
prefilter = '''
matchesAny(attributes[?"path"].orValue(""), [
  r"""(?i)\.(?:bmp|gif|jpe?g|png|svg)$""",
  r"""(?:^|/)node_modules(?:/.*)?$""",
  r"""(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$"""
])
||
(
  attributes[?"git.author_name"].orValue("").endsWith("[bot]") &&
  matchesAny(attributes[?"path"].orValue(""), [r"""(?:^|/)fixtures/"""])
)
'''
```

---

## `filter` — Per-match filtering

`filter` runs after a regex match is found. It has access to both `attributes` and `finding`. It exists at the **global level** (applies to every match from every rule) and at the **per-rule level** (applies only to matches from that rule).

Rule-level filters are applied in addition to the global filter — both must pass for a finding to be kept.

### Variables

| Variable | Type | Description |
|---|---|---|
| `attributes` | `map<string, string>` | Metadata about the source fragment. Same keys as prefilter. |
| `finding` | `map<string, string>` | The matched secret. See [Finding Keys](#finding-keys) below. |

### Finding Keys

| Key | Description |
|---|---|
| `finding["secret"]` | The extracted secret value (the captured group). |
| `finding["match"]` | The full regex match string. |
| `finding["line"]` | The full line of code containing the match. |
| `finding["rule_id"]` | The rule's ID string. |
| `finding["description"]` | The rule's description string. |

### Example

```toml
# Global filter — applies to all rules
filter = '''
matchesAny(finding["secret"], [
  r"""(?i)^(?:true|false|null|undefined|example|changeme|placeholder)$""",
  r"""^\$\{[A-Za-z_]+\}$"""
])
||
(
  entropy(finding["secret"]) <= 2.5 &&
  failsTokenEfficiency(finding["secret"])
)
'''

# Per-rule filter — applies only to this rule
[[rules]]
id = "aws-access-key"
filter = '''
entropy(finding["secret"]) <= 3.5
'''
```

---

## `validate` — Liveness verification

`validate` is **per-rule only** and runs when `--validation` is passed. It fires an HTTP request to check whether the secret is live. Responses are cached in-memory so duplicate secrets only trigger one request.

> See [validation.md](validation.md) for a full reference on the validate environment.

### Variables

| Variable | Type | Description |
|---|---|---|
| `secret` | `string` | The extracted secret value. |
| `captures` | `map<string, string>` | Named capture groups from the rule's regex. |

### Example

```toml
[[rules]]
id = "my-service-token"
validate = '''
cel.bind(r,
  http.get("https://api.example.com/me", {"Authorization": "Bearer " + secret}),
  r.status == 200 ? {"result": "valid"}
  : r.status in [401, 403] ? {"result": "invalid", "reason": "Unauthorized"}
  : unknown(r)
)
'''
```

---

## Shared functions

These functions are available in both `prefilter` and `filter` environments.

### `matchesAny(string, list<string>) → bool`

Returns `true` if the string matches any of the provided regular expression patterns. Patterns are joined and compiled once, then cached — so a fixed literal list in a translated allowlist pays only one regex evaluation per call.

```cel
matchesAny(attributes[?"path"].orValue(""), [r"""(?i)\.md$""", r"""(?i)\.txt$"""])
matchesAny(finding["secret"], [r"""^(?i:fake|test|mock)"""])
```

### `containsAny(string, list<string>) → bool`

Returns `true` if the string contains any of the provided substrings (case-insensitive, uses an Aho-Corasick trie for efficiency). The haystack is lowercased before matching, so search terms should be lowercase.

```cel
containsAny(finding["secret"], ["example", "placeholder", "changeme"])
containsAny(attributes[?"git.author_name"].orValue(""), ["dependabot", "renovate"])
```

> **Note:** because the haystack is lowercased, terms in the list must also be lowercase to match. `"EXAMPLE"` will never match — use `"example"`.

### `entropy(string) → double`

Returns the Shannon entropy (bits) of the string, computed over the byte distribution. Higher values mean more random-looking content.

Typical thresholds:

| Entropy range | Interpretation |
|---|---|
| `< 2.5` | Very low — likely natural language or a repeated character |
| `2.5 – 3.5` | Low — short words, simple patterns |
| `3.5 – 4.5` | Medium — plausible secret range |
| `> 4.5` | High — looks like a real random secret |

```cel
// Discard if the secret has suspiciously low entropy
entropy(finding["secret"]) <= 3.5
```

### `failsTokenEfficiency(string) → bool`

Returns `true` if the string tokenizes too efficiently using BPE (Byte-Pair Encoding), meaning it looks like natural language rather than a random secret. Useful as a complement to entropy for catching human-readable false positives.

```cel
// Discard if the secret looks like plain English
entropy(finding["secret"]) <= 2.5 && failsTokenEfficiency(finding["secret"])
```

---

## Attribute Keys

The `attributes` map is populated by the source that yielded the fragment. Not all keys are present in all sources — use the optional accessor `attributes[?"key"].orValue("")` to safely read missing keys. Attributes are set by the source authors in the source files. [Full list of attributes](sources/attribute.go).


---

## Safe attribute access

If a key is absent, a direct map access like `attributes["git.sha"]` will cause a CEL runtime error. Always use the optional accessor:

```cel
# Safe — returns "" if the key is absent
attributes[?"git.sha"].orValue("")

# Safe — returns a default if absent
attributes[?"git.platform"].orValue("unknown")
```

---

## CEL standard library extras

Both `prefilter` and `filter` also include the CEL string extensions (`ext.Strings`) and the `cel.bind` macro (`ext.Bindings`), which lets you avoid repeating sub-expressions:

```cel
cel.bind(secret, finding["secret"],
  entropy(secret) <= 3.5 || failsTokenEfficiency(secret)
)
```

---

## Tips for rule authors

**Start with `filter`, not `prefilter`.** Unless you're sure a whole path or commit should be skipped, use `filter` where the `finding` is available to make more precise decisions.

**Prefer `containsAny` over `matchesAny` for fixed strings.** The Aho-Corasick trie is faster than a regex for substring lookups.

**Combine `entropy` + `failsTokenEfficiency` for placeholder suppression.** Either check alone produces false positives; together they're much more accurate:
```cel
entropy(finding["secret"]) <= 2.5 && failsTokenEfficiency(finding["secret"])
```

**Test your CEL expressions with `--log-level=debug`.** Translated CEL expressions are logged at debug level, so you can see exactly what the filter looks like after allowlist translation.

**Per-rule filters compose with the global filter.** If either the global or the rule-level filter returns `true`, the finding is discarded. You don't need to repeat global checks in per-rule filters.
