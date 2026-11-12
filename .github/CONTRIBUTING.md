# Contribution guidelines

## General

### Issues

If you have a feature or bug fix you would like to contribute please check if
there are any open issues describing your proposed addition. If there are open
issues, make a comment stating you are working on fixing or implementing said
issue. If not, then please open an issue describing your addition. Make sure to
link your PR to an issue.

### Pull Requests

Fill out the template as best you can. Make sure your tests pass. If you see a
PR that isn't one you opened and want it introduced in the next release,
give it a :thumbsup: on the PR description.

### Code organization

- **Keep a struct definition and all of its methods in the same file.** This
  includes exported and unexported methods. Add new methods to that file.
- Keep supporting helpers alongside the code they serve. Do not create a file
  for each feature, operation, or small addition. File length alone is not a
  reason to split a struct's implementation.
- Read the existing package before adding files. Follow its ownership and
  layout; do not reintroduce files that were deliberately consolidated.
- Use `analyze/analyzer.go` as the model: `Analyzer`, its direct credential
  operations, streaming methods, and requirement queries all live together.

### Tests

Tests should protect meaningful behavior and be easy to find and maintain.
More test files and more assertions are not goals in themselves.

- **Use the existing test file for the behavior you are changing.** Read the
  package's tests before adding another file. For example, a regression proving
  that scans never execute revocation belongs in `pipeline/pipeline_test.go`.
- **Do not create a new test file for every feature, bug fix, or PR.** A single
  regression or a few related cases usually belong alongside existing coverage.
  Create a separate file when it owns a distinct area of behavior or a substantial
  test suite whose separation makes the package easier to navigate.
- Extend an existing table or reuse its fixtures when the new case exercises
  the same contract. Avoid duplicating setup and helpers across small files.
- Test observable results and consequential failure modes: incorrect findings,
  leaked credentials, unintended provider requests, broken cancellation, or
  incorrect command behavior. Avoid tests that merely restate implementation
  details, check that code contains a string, or repeat coverage at every layer
  without catching a different failure.
- Straightforward renames and documentation edits generally do not need new
  tests. Update affected existing tests and run the relevant checks.
- During review, consolidate overlapping tests and remove redundant assertions.
  Preserve useful regression coverage when reorganizing files.

## Adding new Betterleaks rules

See the [provider guide](../docs/provider_guide.md) for credential design,
validation and revocation API contracts, and testing the credential lifecycle.

Rules for the [default configuration](../config/betterleaks.toml) live in
[`rules/`](../rules), one file per provider. Rules that are not specific to a
provider, such as generic API keys and passwords, live in
[`rules/generic/`](../rules/generic). `config/betterleaks.toml` is generated
from them.

1. Run `make newrule NAME={provider}` to create `rules/{provider}.go` from a
   template, or add to the provider's existing file. Each rule registers
   itself with `rulebuilder.Add`; there is no list to update.
   The helpers live in [`internal/rulebuilder`](../internal/rulebuilder).
   Here's a rule modeled on `beamer.go`, with comments added for context:

   ```golang
   package rules

   import (
       "github.com/betterleaks/betterleaks/v2/config"
       "github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
   )

   var _ = rulebuilder.Add(config.Rule{
       // Unique ID for the rule
       ID: "beamer-api-token",

       // Human readable description of the rule
       Description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
       Confidence:  "medium",

       // Regex used for detecting secrets. See below for more details
       Regex: rulebuilder.Assignment([]string{"beamer"}, `(?i)b_[a-z0-9=_\-]{44}`),

       // Lowercase keywords used for string matching on fragments (think of this as a prefilter)
       Keywords: []string{"beamer"},

       // Inputs the rule must and must not detect
       Tests: []config.RuleTest{
           rulebuilder.Match("assignment", `beamerToken = "b_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903f"`, "b_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903f"),
           rulebuilder.NoMatch("firmware file name", "R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu"),
       },
   })
   ```

   To help with maintenance, _most_ rules should be uniform, so build the regex
   with one of two `rulebuilder` helpers:

   - `Token(pattern)` for a credential distinctive enough to stand alone. It
     adds the standard token boundaries. Pulumi's API token has the prefix
     `pul-`, which is unique enough for `Token`.
   - `Assignment(names, pattern)` for a credential that is only recognizable
     next to a name, such as `BEAMER_TOKEN = "b_..."`. Beamer's `b_` prefix is
     not unique enough on its own. Names are case-insensitive regex fragments
     and should match the rule's `Keywords`: both tell Betterleaks "_at least
     one of these strings must be present to be considered a leak_".

   A leading `(?i)` makes the pattern case-insensitive. If a token's prefix has
   more than `3` characters then you could probably get away with `Token`.
   Write a raw `Regex` only when neither helper fits.

   Both helpers are tested once across common assignment syntaxes (env files,
   JSON, YAML, source code), so a rule's tests only need to prove its format:

   - `Match(name, input, secret)`: `input` must produce exactly one finding,
     `secret`.
   - `NoMatch(name, input)`: `input` must produce no findings.
   - `MatchComponent` and `NoMatchComponent` do the same for a `SkipReport`
     component rule, whose matches are never reported on their own.

   Name each test for what it checks, such as "wrong prefix" or "placeholder",
   and use literal values rather than generated ones. For expected component
   sets, named captures, or paths, write a `config.RuleTest` literal; see
   [rule tests](../docs/config.md#check-a-config-and-its-rule-tests).

2. If you want to include filters like entropy checking, attribute filtering, or Token Efficiency filtering, set the rule's `FilterExpr` field. For more information, check out the [config doc](/docs/config.md)
Example simple `filter`:
```
filter = '''
    entropy(finding["secret"]) <= 3.5 ||
    failsTokenEfficiency(finding["secret"])
'''
```

3. Betterleaks supports secrets validation, or liveliness checking, so we expect new rules to have validation logic. Expr powers the validation engine. Set the rule's `ValidateExpr` field. For more information, check out the [config doc](/docs/config.md)
Example `validate`:
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

   Multipart rules set `Components` on `config.Rule`. Validation expressions
   read the primary rule's named groups from `finding["captures"]`, component
   secrets from `components["rule-id"]?.secret ?? ""`, and component named
   groups from `components["rule-id"]?.captures?.group ?? ""`.

4. When the provider exposes identity, scope, or permission information, add an
   `AnalyzeExpr`. Pass data already returned by validation through its reserved
   `analysis` object and read it from `validation.analysis`. Do not repeat a
   provider request merely to obtain data validation already had.

   Keep analysis metadata focused on triage: credential ownership, actionable
   permissions, and affected resources. Omit empty/default values and routine
   provider settings that do not help assess or remediate the finding.

### Provider safety for validation and analysis

Validation and analysis run against real provider APIs. Be polite:

- Target five or fewer analysis requests per credential. Reuse
  `validation.analysis` whenever possible.
- Prefer `GET` for validation. Use `POST` only when it is non-stateful and
  cannot create or modify provider resources.
- Avoid broad resource enumeration and unbounded pagination.
- Document the endpoints used. Tests should verify request methods, paths, and
  counts with an injected HTTP transport.

If a provider cannot be checked safely, omit validation or analysis.

Credential revocation belongs exclusively in a rule's optional `RevokeExpr`
(`revoke` in TOML). Only the `revoke` command executes it; do not put revocation
requests in validation or analysis expressions. Test lookup-then-revoke workflows
with a local HTTP server, including failed lookups, missing IDs, request limits,
and evidence confirming invalidation. Return `revoked` only when invalidation is
confirmed; an asynchronous acceptance response alone is `unknown`. See the
[revocation contract](../docs/config.md#explicit-credential-revocation).

5. Run your provider's tests while you iterate, then regenerate the default
   config:

   ```sh
   go test ./rules -run TestRules/beamer
   make config
   ```

   `make config` runs every rule test, then `go generate ./rules`. It also
   checks that each rule still reports its secrets with every rule active, so
   a new rule can't hide an existing one.

6. Check out your new rules in `config/betterleaks.toml`, commit it together
   with your `rules/` file, and open a PR. CI fails if the generated config is
   out of date. If `config/betterleaks.toml` conflicts with another change,
   don't merge it by hand: run `make config` and commit the result.
