package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ProofFullAccessAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "proof-full-access-api-key",
		Description: "Proof production full-access API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`prf_(?:cli_)?[A-Za-z0-9_-]{20,80}`, false),
		Keywords:    []string{"prf_"},
		ValidateExpr: `let r = http.post("https://api.proof.com/v1/transactions", {
    "ApiKey": finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{}"); r.status == 422 && (r.body contains "signer") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: `filter.matchesAny(finding["secret"], ["^prf_(?:cli_)?test_"])
|| ` + utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PROOF_API_KEY=prf_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{36}`, 3.5),
		"PROOF_API_KEY=prf_cli_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{36}`, 3.5),
	}
	fps := []string{
		`PROOF_API_KEY=prf_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456`,
		`PROOF_API_KEY=prf_cli_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456`,
		`PROOF_API_KEY=prf_short`,
	}
	return utils.Validate(r, tps, fps)
}
