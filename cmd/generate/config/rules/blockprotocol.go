package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func BlockProtocolAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "block-protocol-api-key",
		Description: "Detected a Block Protocol API key, which may expose private hub resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`b10ck5\.[A-Za-z0-9]{32}\.[A-Za-z0-9]{36}`, false),
		Keywords:    []string{"b10ck5."},
		ValidateExpr: `let r = http.get("https://blockprotocol.org/api/blocks", {
    "x-api-key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{`BLOCK_PROTOCOL_API_KEY=b10ck5.R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7.Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xT8c`},
		[]string{
			`BLOCK_PROTOCOL_API_KEY=b10ck5.short.Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xT8c`,
			`BLOCK_PROTOCOL_API_KEY=b10ck5.R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7.Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xT8c_extra`,
		},
	)
}
