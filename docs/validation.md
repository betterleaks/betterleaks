## Secrets Validation
Secrets Validation is a new feature in Betterleaks. By default, validation is disabled. To enable it, pass the `--validation` flag.

Betterleaks can automatically verify if a detected secret is live by making an HTTP request defined in the rule's validate field. Validation runs asynchronously, and responses are cached in-memory so duplicate secrets only trigger a single network request.

### CEL Expressions
Rules use [CEL (Common Expression Language)](https://cel.dev/) for validation logic. The expression receives the captured secret, fires an HTTP request (more validation kinds to come), and returns a status map.

### Variables & Functions:

- `secret` (string): The captured secret value.
- `captures` (map): Named capture groups from the rule's regex.
- `http.get(url, headers)` / `http.post(url, headers, body)`: Fires the HTTP request.
- `cel.bind(name, value, expr)`: Binds a variable to avoid repeating sub-expressions.
- `unknown(response)`: Helper returning `{"result": "unknown", "reason": "HTTP <status>"}`.

### The Response Object (r):
- `r.status` (int): HTTP status code.
- `r.body` (string): Raw response body.
- `r.json` (dyn): Parsed JSON body.
- `r.headers` (map): Response headers (all keys lowercased).

### Result Format
Expressions should return a map with a `"result"` key set to `valid`, `invalid`, `revoked`, `unknown`, or `error`. Any additional keys in the map are attached to the finding as metadata.

Example
Here is a standard validation block for a GitHub Personal Access Token. It uses CEL's optional chaining (.? and .orValue()) to safely extract metadata from the JSON response:

```TOML
[[rules]]
id = "github-pat"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]
validate = '''
  cel.bind(r,
    http.get("https://api.github.com/user", {
      "Accept": "application/vnd.github+json",
      "Authorization": "token " + secret
    }),
    r.status == 200 ? {
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
Note: For more complex validation setups—such as dynamically constructing URLs, using Basic Auth, or validating multi-part composite rules ([[rules.required]])—check out the existing examples in our built-in rules directory.