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

## Adding new Betterleaks rules

If you want to add a new rule to the [default configuration](config/betterleaks.toml) then follow these steps.

1. Create a `cmd/generate/config/rules/{provider}.go` file.
   This file is used to generate a new rule.
   Let's look at `beamer.go` for example. Comments have been added for context.

   ```golang
   func Beamer() *config.Rule {
       // Define Rule
       r := config.Rule{
           // Human readable description of the rule
           Description: "Beamer API token",

           // Unique ID for the rule
           RuleID:      "beamer-api-token",

           // Regex used for detecting secrets. See regex section below for more details
           Regex: GenerateSemiGenericRegex([]string{"beamer"}, `b_[a-z0-9=_\-]{44}`, true)

           // Keywords used for string matching on fragments (think of this as a prefilter)
           Keywords: []string{"beamer"},
       }

       // validate the keyword, regex, and filters work
       tps := []string{
           generateSampleSecret("beamer", "b_"+secrets.NewSecret(alphaNumericExtended("44"))),
       }
       fps := []string{
           `R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu`,
       }
       return validate(r, tps, fps)
   }
   ```

   Feel free to use this example as a template when writing new rules.
   This file should be fairly self-explanatory except for a few items;
   regex and secret generation. To help with maintence, _most_ rules should
   be uniform. The functions,
   `GenerateSemiGenericRegex` and `GenerateUniqueTokenRegex` (in `cmd/generate/config/rules/rule.go`) will generate rules
   that follow defined patterns.

   The function signatures look like this:

   ```golang
   func GenerateSemiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp

   func GenerateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp
   ```

   `GenerateSemiGenericRegex` accepts a list of identifiers, a regex, and a boolean indicating whether the pattern should be case-insensitive.
   The list of identifiers _should_ match the list of `Keywords` in the rule
   definition above. Both `identifiers` in the `GenerateSemiGenericRegex`
   function _and_ `Keywords` act as filters for Betterleaks telling the program
   "_at least one of these strings must be present to be considered a leak_"

   `GenerateUniqueTokenRegex` just accepts a regex and a boolean indicating whether the pattern should be case-insensitive. If you are writing a rule for a
   token that is unique enough not to require an identifier then you can use
   this function. For example, Pulumi's API Token has the prefix `pul-` which is
   unique enough to use `GenerateUniqueTokenRegex`. But something like Beamer's API
   token that has a `b_` prefix is not unique enough to use `GenerateUniqueTokenRegex`,
   so instead we use `GenerateSemiGenericRegex` and require a `beamer`
   identifier is part of the rule.
   If a token's prefix has more than `3` characters then you could
   probably get away with using `GenerateUniqueTokenRegex`.

   Last thing you'll want to hit before we move on from this file is the
   validation part. You can use `generateSampleSecret` to create a secret for the
   true positives (`tps` in the example above) used in `validate`.

2. If you want to include filters like entropy checking, attribute filtering, or Token Efficiency filtering, set the rule's `Filter` field. For more information, check out the [config doc](/docs/config.md)
Example simple `filter`:
```
filter = '''
    filter.entropy(finding["secret"]) <= 3.5 ||
    filter.failsTokenEfficiency(finding["secret"])
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

5. Update `cmd/generate/config/main.go`. Extend `configRules` slice with
   the `rules.Beamer(),` in `main()`. Try and keep
   this alphabetically pretty please.

6. Run `make config/betterleaks.toml`

7. Check out your new rules in `config/betterleaks.toml` and see if everything looks good.

8. Open a PR
