package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MidtransProductionServerClientKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "midtrans-production-server-client-key",
		Description: "Midtrans production server or client key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`midtrans`, `mid[_-]?`},
			`Mid-(?:server|client)-[A-Za-z0-9_]{10,20}`,
			true,
		),
		Keywords: []string{"mid-server-", "mid-client-"},
		ValidateExpr: `let r = http.get("https://api.midtrans.com/v2/betterleaks-validation-nonexistent/status", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 || (r.status == 404
    && (r.json?.status_code ?? "") == "404"
    && (r.json?.status_message ?? "") == "The requested resource is not found") ? {
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
		"midtrans.client_key='Mid-client-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_]{16}`, 2.8) + "'",
	}
	fps := []string{
		`MIDTRANS_SERVER_KEY=Mid-server-short`,
		`MIDTRANS_CLIENT_KEY=SB-Mid-client-Xk93PcDP8pMKfhY2`,
	}
	return utils.Validate(r, tps, fps)
}
