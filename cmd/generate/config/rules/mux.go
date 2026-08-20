package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MuxAccessTokenID() *config.Rule {
	r := config.Rule{
		RuleID:      "mux-access-token-id.1",
		Confidence:  "medium",
		Description: "Mux access-token ID, used as a component of the Mux access-token-secret composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`mux[_.-]?(?:access[_.-]?)?token[_.-]?(?:id|identifier)`},
			utils.Hex8_4_4_4_12(),
			true,
		),
		Keywords:   []string{"mux"},
		SkipReport: true,
		Filter:     utils.MinEntropy(3.0),
	}

	tokenID := secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.0)
	tps := []string{
		`MUX_TOKEN_ID=` + tokenID,
		`mux_access_token_id: "` + tokenID + `"`,
	}
	fps := []string{
		`TOKEN_ID=` + tokenID,
		`MUX_TOKEN_ID=00000000-0000-0000-0000-000000000000`,
		`MUX_TOKEN_ID=short`,
	}
	return utils.Validate(r, tps, fps)
}

func MuxAccessTokenSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "mux-access-token-secret.1",
		Confidence:  "high",
		Description: "Mux access-token secret, which may grant access to video, data, or system APIs when paired with its token ID.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`mux[_.-]?(?:access[_.-]?)?token[_.-]?(?:secret|private|key)`},
			`[A-Za-z0-9+/]{75}`,
			false,
		),
		Keywords: []string{"mux"},
		Components: []*config.Component{
			{RuleID: "mux-access-token-id.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.get("https://api.mux.com/video/v1/assets?limit=1", {
    "Authorization": "Basic " + base64.encode(bytes((components["mux-access-token-id.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated Mux token without Video read permission"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	tokenSecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{75}`, 3.5)
	tps := []string{
		`MUX_TOKEN_SECRET=` + tokenSecret,
		`mux_access_token_secret: "` + tokenSecret + `"`,
	}
	fps := []string{
		`TOKEN_SECRET=` + tokenSecret,
		`MUX_TOKEN_SECRET=short`,
		`MUX_TOKEN_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}
