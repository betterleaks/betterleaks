package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "sourcegraph-access-token",
	Confidence:  "high",
	Description: "Sourcegraph is a code search and navigation engine.",
	Regex:       rulebuilder.Token(`(?i)sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}`),
	Keywords:    []string{"sgp_"},
	ValidateExpr: `let r = http.post("https://sourcegraph.com/.api/graphql", {
    "Authorization": "token " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"query\":\"query ValidateToken { site { id } }\"}"); r.status == 200 && (r.json?.data?.site?.id ?? "") != "" ? {
    "result": "valid",
    "metadata": {"site_id": (r.json?.data?.site?.id ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", "sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b", "sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b"),
		rulebuilder.Match("bare secret 2", "sgp_0D697F54cb24238EefB29af05Abf1b505E90950F", "sgp_0D697F54cb24238EefB29af05Abf1b505E90950F"),
		rulebuilder.Match("bare secret 3", "sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42", "sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42"),
		rulebuilder.Match("bare secret 4", "sgp_local_bcD1DA18de0d6476Be0f3BD7Ef9Da4f09b479aE5", "sgp_local_bcD1DA18de0d6476Be0f3BD7Ef9Da4f09b479aE5"),
		rulebuilder.NoMatch("low entropy", "sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa"),
		rulebuilder.NoMatch("invalid case", "sgp_local_d45b6G86aBb0F2Cee943902dbaDBCFCFDD1dA089"),
		rulebuilder.NoMatch("invalid character", "sgp_652d9a2e48FC7E!FcDbEA1BC2E2A6CE23cFe7F7D"),
		rulebuilder.NoMatch("invalid length", "sgp_78Ad84a5B6e8A2fE5B_4085FB0ccaDDd29DB66Fd7FE9bA2C1cdCE8400CD"),
	},
})
