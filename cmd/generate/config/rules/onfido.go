package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OnfidoLiveAPITokenEU() *config.Rule {
	return onfidoLiveAPIToken(
		"onfido-live-api-token-eu",
		`api_live\.[A-Za-z0-9_-]{20,80}`,
		"api_live.",
		"https://api.eu.onfido.com/v3.6/webhooks/",
	)
}

func OnfidoLiveAPITokenUS() *config.Rule {
	return onfidoLiveAPIToken(
		"onfido-live-api-token-us",
		`api_live_us\.[A-Za-z0-9_-]{20,80}`,
		"api_live_us.",
		"https://api.us.onfido.com/v3.6/webhooks/",
	)
}

func OnfidoLiveAPITokenCA() *config.Rule {
	return onfidoLiveAPIToken(
		"onfido-live-api-token-ca",
		`api_live_ca\.[A-Za-z0-9_-]{20,80}`,
		"api_live_ca.",
		"https://api.ca.onfido.com/v3.6/webhooks/",
	)
}

func onfidoLiveAPIToken(ruleID, tokenRegex, keyword, endpoint string) *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      ruleID,
		Description: "Onfido live API token.",
		Regex:       utils.GenerateUniqueTokenRegex(tokenRegex, false),
		Keywords:    []string{keyword},
		ValidateExpr: `let r = http.get("` + endpoint + `", {
    "Authorization": "Token token=" + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"ONFIDO_API_TOKEN=" + keyword + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{32}`, 3.5),
	}
	fps := []string{
		"ONFIDO_API_TOKEN=" + keyword + "short",
		"ONFIDO_API_TOKEN=" + keyword + "00000000000000000000000000000000",
	}
	return utils.Validate(r, tps, fps)
}
