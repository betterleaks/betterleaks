package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func LangSmithPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langchain-langsmith-personal-access-token",
		Description: "LangSmith personal access token.",
		Regex:       regexp.MustCompile(`\b(lsv2_pt_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})`),
		Keywords:    []string{"lsv2_pt_"},
		ValidateExpr: `let r = http.get("https://api.smith.langchain.com/api/v1/api-key/current", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(4.0),
	}

	// validate
	tps := []string{
		`LANGSMITH_API_KEY=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`,
	}
	fps := []string{
		`LANGSMITH_API_KEY=lsv2_pt_short`,
	}
	return utils.Validate(r, tps, fps)
}

func LangSmithServiceKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langchain-langsmith-service-key",
		Description: "LangSmith service API key.",
		Regex:       regexp.MustCompile(`\b(lsv2_sk_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})`),
		Keywords:    []string{"lsv2_sk_"},
		ValidateExpr: `let r = http.get("https://api.smith.langchain.com/api/v1/orgs/current", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(4.0),
	}

	// validate
	tps := []string{
		`LANGSMITH_SERVICE_KEY=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`,
	}
	fps := []string{
		`LANGSMITH_SERVICE_KEY=lsv2_sk_short`,
	}
	return utils.Validate(r, tps, fps)
}
