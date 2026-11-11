package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cloudsmith-api-key",
	Confidence:  "high",
	Description: "Detected a Cloudsmith API key, which may expose package repositories and artifact management operations to unauthorized access.",
	Regex:       Token(`csa_[a-f0-9]{30}[A-Za-z0-9]{6}`),
	Keywords:    []string{"csa_"},
	ValidateExpr: `let r = http.get("https://api.cloudsmith.io/user/self/", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.json?.authenticated ?? false) == true ? {
    "result": "valid",
    "metadata": {"account": (r.json?.slug ?? "")}
  } : r.status in [401, 403] || (r.status == 200 && (r.json?.authenticated ?? false) == false) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("cloudsmith assignment", `cloudsmithToken = "csa_93d7f5d17b39f506a607a3c4f61794Q1phUk"`, "csa_93d7f5d17b39f506a607a3c4f61794Q1phUk"),
		NoMatch("false positive 1", `cloudsmith = "csa_93d7f5d16b39f506a607a3c4f61794Q1phU"`),
		NoMatch("false positive 2", `cloudsmith = "csb_93d7f5d16b39f506a607a3c4f61794Q1phUQ"`),
	},
})
