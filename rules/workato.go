package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "workato-developer-api-token.1",
	Confidence:  "high",
	Description: "Workato Developer API token.",
	Regex:       rulebuilder.Token(`wrka(?:[a-z]{2})?-eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{64,}`),
	Keywords:    []string{"wrka"},
	ValidateExpr: `let token = finding["secret"];
let host = matchesAny(token, ["^wrkaeu-"]) ? "https://app.eu.workato.com" :
  matchesAny(token, ["^wrkajp-"]) ? "https://app.jp.workato.com" :
  matchesAny(token, ["^wrkasg-"]) ? "https://app.sg.workato.com" :
  matchesAny(token, ["^wrkaau-"]) ? "https://app.au.workato.com" :
  matchesAny(token, ["^wrkail-"]) ? "https://app.il.workato.com" :
  matchesAny(token, ["^wrkacn-"]) ? "https://app.workatoapp.cn" :
  matchesAny(token, ["^wrkakr-"]) ? "https://app.kr.workato.com" :
  "https://www.workato.com";
let r = http.get(host + "/api/users/me", {
    "Authorization": "Bearer " + token,
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"id\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but workspace-details access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "WORKATO_API_TOKEN=wrka-eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZXBsb3ktYm90IiwianRpIjoiY2kxMjM0NTY3LXRlc3QiLCJleHAiOjIwMDAwMDAwMDB9.aQ1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX8yZ9AbCdEfGhIjKlMnOpQr", "wrka-eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZXBsb3ktYm90IiwianRpIjoiY2kxMjM0NTY3LXRlc3QiLCJleHAiOjIwMDAwMDAwMDB9.aQ1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX8yZ9AbCdEfGhIjKlMnOpQr"),
		rulebuilder.Match("true positive 2", "WORKATO_EU_API_TOKEN=wrkaeu-eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkZXBsb3ktYm90LXVzZXIifQ.aQ1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1k", "wrkaeu-eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkZXBsb3ktYm90LXVzZXIifQ.aQ1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1k"),
		rulebuilder.NoMatch("false positive 1", "WORKATO_API_TOKEN=wrka-short"),
		rulebuilder.NoMatch("false positive 2", "WORKATO_API_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvdGhlciJ9.signature"),
	},
})
