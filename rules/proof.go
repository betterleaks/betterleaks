package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "proof-full-access-api-key",
	Confidence:  "high",
	Description: "Proof production full-access API key.",
	Regex:       Token(`prf_(?:cli_)?[A-Za-z0-9_-]{20,80}`),
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
	FilterExpr: `matchesAny(finding["secret"], ["^prf_(?:cli_)?test_"])
|| ` + MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "PROOF_API_KEY=prf_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_B", "prf_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_B"),
		Match("true positive 2", "PROOF_API_KEY=prf_cli_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_B", "prf_cli_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_B"),
		NoMatch("false positive 1", "PROOF_API_KEY=prf_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
		NoMatch("false positive 2", "PROOF_API_KEY=prf_cli_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
		NoMatch("false positive 3", "PROOF_API_KEY=prf_short"),
	},
})
