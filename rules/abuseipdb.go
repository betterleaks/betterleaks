package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "abuseipdb-api-key.1",
	Confidence:  "high",
	Description: "AbuseIPDB API key, which may allow access to IP reputation data and abuse-reporting APIs.",
	Regex:       rulebuilder.Assignment([]string{"abuseipdb"}, `(?i)[a-f0-9]{80}`),
	Keywords:    []string{"abuseipdb"},
	ValidateExpr: `let r = http.get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1", {
    "Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"ipAddress\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ABUSEIPDB_API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4", "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4"),
		rulebuilder.Match("true positive 2", `abuseipdb token: "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4"),
		rulebuilder.NoMatch("false positive 1", "API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4"),
		rulebuilder.NoMatch("false positive 2", "ABUSEIPDB_API_KEY=short"),
		rulebuilder.NoMatch("false positive 3", "ABUSEIPDB_API_KEY=00000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	},
})
