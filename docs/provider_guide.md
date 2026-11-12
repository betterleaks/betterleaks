# Design API keys for secret scanning

Design for detection before issuing credentials. A recognizable format and a
published rule help customers find exposed keys; validation and revocation help
them confirm and contain the exposure.

This guide is for providers designing credentials and adding support to
Betterleaks. See the [config reference](config.md) for rule fields and Expr
bindings, and the [contribution guide](../.github/CONTRIBUTING.md#adding-new-betterleaks-rules)
for the rule authoring workflow.

## Use a distinctive prefix

A unique, greppable prefix identifies the issuer and reduces false positives.
Include the credential type, with version and environment markers where useful:

```text
acmecloud_pat_v1_live_<64 lowercase hexadecimal characters>
acmecloud_pat_v1_test_<64 lowercase hexadecimal characters>
acmecloud_svc_v1_live_<64 lowercase hexadecimal characters>
```

Keep prefixes stable and case-sensitive, and distinguish secret credentials from
public IDs. Check existing formats before choosing a namespace. Sandbox keys
are still secrets. See [GitHub's partner guidance](https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program#identify-your-secrets-and-create-regular-expressions).

## Preserve randomness

For a new opaque bearer key, start with **32 cryptographically random bytes**:
64 hexadecimal characters or 43 unpadded base64url characters. Add the prefix
without shortening the random body. Fixed prefixes, timestamps, and checksums
add no independent randomness. [OWASP entropy guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy).

Document the alphabet, case, length, encoding, padding, and supported versions.
Avoid personal data in the token. Use synthetic, never-issued values in rule
tests.

## Add an offline checksum

A public checksum lets scanners reject malformed candidates without an API call.
It adds no secret entropy and does not prove issuance or liveness.
[GitHub's token design](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/)
uses this approach with CRC32.

One option using an existing binding is a truncated SHA-256 checksum:

1. Generate 32 random bytes and encode them as 64 lowercase hex characters.
2. Prepend `acmecloud_pat_v1_live_` to form the body.
3. Hash the exact UTF-8 body, without a newline. Append `_` and the first eight
   characters of the lowercase hex digest.

Publish the algorithm and test vectors. This synthetic token is one such vector:

```text
acmecloud_pat_v1_live_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f_8e7ad039
```

The rule's [Expr filter](config.md#filtering) discards checksum mismatches
(`true` means discard):

```toml
[[rules]]
id = "acmecloud-api-key"
description = "AcmeCloud personal access token"
regex = '''\bacmecloud_pat_v1_live_[0-9a-f]{64}_[0-9a-f]{8}\b'''
keywords = ["acmecloud_pat_v1_live_"]
filter = '''
let token = finding["secret"];
crypto.sha256(token[:len(token)-9])[:8] != token[len(token)-8:]
'''
```

## Provide a validation API

Validation tells responders whether an exposed key still works. Offer a
read-only HTTPS endpoint authenticated by the credential, without requiring
unrelated product permissions: restricted keys can still be valid.

Document responses for active, invalid, expired, and revoked keys, plus rate
limits and temporary failures. OAuth services can use
[RFC 7662 introspection](https://www.rfc-editor.org/rfc/rfc7662.html#section-2),
with its authorization requirements.

For this fictional API, `GET /tokens/self` returns `200 {"active": true}` for an
active key and `401 {"error": "invalid_token"}` for an invalid key. Add this
`validate` field to the same rule:

```toml
validate = '''
let r = http.get("https://api.acmecloud.example/tokens/self", {
  "Authorization": "Bearer " + finding["secret"]
});
r.status == 200 && type(r.json) == "map" && r.json?.active == true ? {"result": "valid"}
  : r.status == 401 && type(r.json) == "map" && r.json?.error == "invalid_token" ? {"result": "invalid"}
  : validate.unknown(r)
'''
```

An HTTP 200 alone is insufficient. Return `unknown` for ambiguous responses,
including permission failures. Identity, expiry, and scopes help responders
assess impact; [analysis expressions](config.md#validation-and-credential-analysis)
can reuse this evidence through `validation.analysis`. Keep secrets out of
response metadata and logs.

## Make revocation observable

Revocation lets responders stop use of an exposed key without disabling the
whole account. Support individual credentials, document authorization and repeat
requests, and distinguish completed invalidation from queued work.

Here, `DELETE /tokens/self` authenticates with the key and returns `204` only once
it is unusable. Add this `revoke` field to the same rule:

```toml
revoke = '''
let r = http.delete("https://api.acmecloud.example/tokens/self", {
  "Authorization": "Bearer " + finding["secret"]
});
r.status == 204 ? {"result": "revoked"} : revoke.unknown(r)
'''
```

Document propagation delays and effects on related keys. OAuth revocation follows
[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2), where HTTP 200
also covers an already-invalid token. Support expiry and rotation alongside
revocation. Betterleaks runs revocation only through the explicit `revoke`
command; see the [revocation contract](config.md#explicit-credential-revocation).

## Add and test your rule

From the Betterleaks repository root, run `make newrule NAME=acmecloud`, or edit
the provider's existing file in [`rules/`](../rules). Replace the starter fields
with your format and expressions. The TOML `filter`, `validate`, `analyze`, and
`revoke` fields correspond to `FilterExpr`, `ValidateExpr`, `AnalyzeExpr`, and
`RevokeExpr` on the Go `config.Rule`.

Add synthetic detection fixtures covering checksum mismatches, boundaries, and
incorrect lengths. Rules register with `rulebuilder.Add`; there is no provider
list to update. Run the focused tests, then regenerate the default configuration:

```sh
go test ./rules -run TestRules/acmecloud
make config
betterleaks config check config/betterleaks.toml
```

The Go commands require Go 1.26+. `make config` runs the rule tests and regenerates
`config/betterleaks.toml`. `config check` runs detection fixtures and compiles all
expressions, including validation and revocation, without executing provider
requests. See the [contribution guide](../.github/CONTRIBUTING.md#adding-new-betterleaks-rules)
for the full workflow.

Test API behavior separately with Betterleaks v2 and a disposable sandbox key.
After replacing the fictional endpoints, use the same key for this lifecycle:

```sh
printf '%s\n' "$ACME_TEST_TOKEN" |
  betterleaks validate -c config/betterleaks.toml --rule acmecloud-api-key --simple
printf '%s\n' "$ACME_TEST_TOKEN" |
  betterleaks revoke -c config/betterleaks.toml --rule acmecloud-api-key --simple
printf '%s\n' "$ACME_TEST_TOKEN" |
  betterleaks validate -c config/betterleaks.toml --rule acmecloud-api-key --simple
```

Expect `VALID`, `REVOKED`, then `INVALID` for this API contract. In vendor CI,
assert the reported status (`--jsonl` provides structured output); a successful
command exit alone does not establish validity. Also test restricted and expired
keys, malformed responses, rate limits, and queued revocations.

Submit the rule, synthetic fixtures, generated configuration, and API
documentation in a PR. Keep working keys out of fixtures and preserve older
formats while issued keys remain valid. When the format changes, rerun these
checks in vendor CI and submit the updated rule.
