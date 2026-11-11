package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cursor-api-key",
	Confidence:  "medium",
	Description: "Detected a Cursor Integrations API Key, which may expose AI-assisted development services to unauthorized access.",
	Regex:       Assignment([]string{"cursor"}, `(?i)key_[0-9a-f]{64}`),
	Keywords:    []string{"cursor"},
	ValidateExpr: `let r = http.get("https://api.cursor.com/v0/me", {
    "Accept": "application/json",
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"]))
  }); r.status == 200 && (r.body contains '"userEmail"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("cursor assignment", `cursorToken = "key_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "key_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		NoMatch("Too short", "cursor_key = key_8c5a7657fc397e114def1b51dd52041"),
		NoMatch("Wrong prefix", "cursor_key = tok_8c5a7657fc397e114def1b51dd520410ad50ece61e30b64261ff369ab275ef29"),
	},
})
