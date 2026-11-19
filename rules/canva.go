package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "canva-client-id",
	Confidence:  "high",
	Description: "Detected a Canva Connect API client ID, used as a component of the canva-client-secret composite rule.",
	Regex:       `(?i)\b(?:canva|CANVA_CLIENT_ID)(?:.|[\n\r]){0,32}?(?:client[_\s-]*id|app[_\s-]*id)(?:.|[\n\r]){0,16}?\b(OC-[A-Za-z0-9_-]{8,16})\b`,
	Keywords:    []string{"canva"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "canva client id: OC-AZ2dqZiY_lec", "OC-AZ2dqZiY_lec"),
		rulebuilder.MatchComponent("true positive 2", "CANVA_CLIENT_ID=OC-FAB12-AbCdEf", "OC-FAB12-AbCdEf"),
		rulebuilder.NoMatchComponent("false positive 1", "client id: OC-AZ2dqZiY_lec"),
		rulebuilder.NoMatchComponent("false positive 2", "CANVA_CLIENT_ID=OC-short"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "canva-client-secret",
	Confidence:  "high",
	Description: "Detected a Canva Connect API client secret, which may allow unauthorized OAuth client authentication when paired with a client ID.",
	Regex:       `\b(cnvca[a-zA-Z0-9_-]{51})\b`,
	Keywords:    []string{"cnvca"},
	Components: []config.Component{
		{RuleID: "canva-client-id"},
	},
	ValidateExpr: `let r = http.post("https://api.canva.com/rest/v1/oauth/token", {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  },
  "grant_type=authorization_code&client_id=" + (components["canva-client-id"]?.secret ?? "") +
  "&client_secret=" + finding["secret"] +
  "&code_verifier=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefgh&code=invalid"); r.status == 400 && (r.body contains "\"invalid_grant\"") && !(r.body contains "\"invalid_client\"") ? {
    "result": "valid"
  } : r.status in [400, 401, 403] && (r.body contains "\"invalid_client\"") ? {
    "result": "invalid",
    "reason": "Invalid client"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "CANVA_CLIENT_SECRET=cnvcav3RRFkl36rsXClN3-Dsygjl_oGT1-xMhXV70oxnGi6s811bfada\ncanva client id: OC-AZ2dqZiY_lec",
			Expect: []config.ExpectedFinding{
				{Secret: "cnvcav3RRFkl36rsXClN3-Dsygjl_oGT1-xMhXV70oxnGi6s811bfada", ComponentSets: []map[string]string{{"canva-client-id": "OC-AZ2dqZiY_lec"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "CANVA_CLIENT_SECRET=cnvcav3RRFkl36rsXClN3-Dsygjl_oGT1-xMhXV70oxnGi6s811bfad"),
	},
})
