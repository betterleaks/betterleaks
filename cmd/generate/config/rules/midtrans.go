package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MidtransProductionServerKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "midtrans-production-server-key",
		Description: "Midtrans production server key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"midtrans"}, `Mid-server-[A-Za-z0-9_]{10,20}`, true),
		Keywords:    []string{"midtrans"},
		ValidateExpr: `let r = http.get("https://api.midtrans.com/v2/betterleaks-validation-nonexistent/status", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status in [200, 404] ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(2.8),
	}

	// validate
	tps := []string{
		"MIDTRANS_SERVER_KEY=Mid-server-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_]{16}`, 2.8),
	}
	fps := []string{
		`MIDTRANS_SERVER_KEY=Mid-client-Xk93PcDP8pMKfhY2`,
		`MIDTRANS_SERVER_KEY=Mid-server-short`,
	}
	return utils.Validate(r, tps, fps)
}
