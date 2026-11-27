package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "zhipu-api-key",
	Confidence:  "high",
	Description: "Detected a Zhipu AI API key, which may allow unauthorized access to BigModel GLM services and resources.",
	Regex:       rulebuilder.Assignment([]string{"zhipu", "bigmodel"}, `(?i)[a-f0-9]{32}\.[A-Za-z0-9]{16,17}`),
	Keywords:    []string{"zhipu", "bigmodel"},
	ValidateExpr: `let r = http.get("https://open.bigmodel.cn/api/paas/v4/models", {"Authorization": "Bearer " + finding["secret"]});
(r.status in [200]) ? {"result": "valid"} :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `zhipu = "b02569a95cafbb3a7dc8d0c7f0c733cb.3jh5I4AJ8Q6JaYEfW"`, `b02569a95cafbb3a7dc8d0c7f0c733cb.3jh5I4AJ8Q6JaYEfW`),
		rulebuilder.NoMatch("near miss 1", `zhipu = "b072711511b393692cdf537deb623ef.Im8eri9zT1kjtsPK"`),
		rulebuilder.NoMatch("near miss 2", `zhipu = "242866c7dc3871b40e81ac4b113797fc.5Q1j86T8IeLjeii"`),
	},
})
