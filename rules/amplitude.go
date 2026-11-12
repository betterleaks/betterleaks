package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "amplitude-secret-key",
	Confidence:  "medium",
	Description: "Detected an Amplitude secret key, which may allow unauthorized event ingestion or access to Amplitude API functionality.",
	Regex:       `(?i)\bamplitude(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN|AUTHORIZATION)(?:.|[\n\r]){0,16}?\b([a-f0-9]{32})\b`,
	Keywords:    []string{"amplitude"},
	ValidateExpr: `let r = http.post("https://api2.amplitude.com/2/httpapi", {
    "Content-Type": "application/json",
    "Accept": "*/*"
  },
  "{" +
    "\"api_key\":" + toJSON(finding["secret"]) + "," +
    "\"events\":[{" +
      "\"user_id\":\"203201202\"," +
      "\"device_id\":\"C8F9E604-F01A-4BD9-95C6-8E5357DF265D\"," +
      "\"event_type\":\"watch_tutorial\"" +
    "}]" +
  "}"); r.status == 200 && (r.body contains "\"code\":200") ? {
    "result": "valid"
  } : r.status in [400, 401, 403] ? {
    "result": "invalid",
    "reason": (r.json?.error ?? "Unauthorized")
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "amplitude_api_key=8b6f8d6594749cb659b1be03e6a0a2e7", "8b6f8d6594749cb659b1be03e6a0a2e7"),
		rulebuilder.Match("true positive 2", "AMPLITUDE_API_KEY=ef929907c3923e8f3da83c24f0255aa6", "ef929907c3923e8f3da83c24f0255aa6"),
		rulebuilder.Match("true positive 3", "AMPLITUDE_SECRET_KEY=8b6f8d6594749cb659b1be03e6a0a2e7", "8b6f8d6594749cb659b1be03e6a0a2e7"),
		rulebuilder.NoMatch("false positive 1", "api_key=8b6f8d6594749cb659b1be03e6a0a2e7"),
		rulebuilder.NoMatch("false positive 2", "AMPLITUDE_SECRET_KEY=8b6f8d6594749cb659b1be03e6a0a2e"),
	},
})
