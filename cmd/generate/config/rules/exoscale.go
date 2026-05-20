package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ExoscaleAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "exoscale-api-key",
		Description: "Identified an Exoscale API key paired with a secret, which together grant programmatic access to Exoscale cloud resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`EXO[a-zA-Z0-9]{24,30}`, false),
		Keywords:    []string{"EXO"},
		Entropy:     3.0,
		RequiredRules: []*config.Required{
			{
				RuleID:      "exoscale-api-secret",
				WithinLines: utils.Ptr(5),
			},
		},
		ValidateCEL: `cel.bind(ts, time.now_unix(),
  cel.bind(sig,
    crypto.hmac_sha256(
      bytes(captures["exoscale-api-secret"]),
      bytes("GET /v2/zone\n\n\n\n" + ts)
    ),
    cel.bind(r,
      http.get("https://api-ch-gva-2.exoscale.com/v2/zone", {
        "Authorization": "EXO2-HMAC-SHA256 credential=" + finding["secret"] + ",expires=" + ts + ",signature=" + base64.encode(sig)
      }),
      r.status == 200 ? {
        "result": "valid"
      } : r.status in [401, 403] ? {
        "result": "invalid",
        "reason": "Unauthorized"
      } : unknown(r)
    )
  )
)`,
	}

	tps := []string{
		`exoscale_api_key = "EXO` + secrets.NewSecretWithEntropy(`[a-f0-9]{24}`, 3.0) + `"`,
	}
	fps := []string{
		// Too short
		`exoscale_api_key = "EXOabc123"`,
		// Wrong prefix
		`exoscale_api_key = "EXAabc123def456ghi789jkl012mno345"`,
	}
	return utils.Validate(r, tps, fps)
}

func ExoscaleAPISecret() *config.Rule {
	r := config.Rule{
		RuleID:      "exoscale-api-secret",
		Description: "Identified an Exoscale API secret, used as a component of the exoscale-api-key composite rule.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"exoscale"}, `[A-Za-z0-9_\-]{40,60}`, true),
		Keywords:    []string{"exoscale"},
		Entropy:     4.0,
		SkipReport:  true,
	}

	tps := utils.GenerateSampleSecrets("exoscale", secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-]{40}`, 4.0))
	return utils.Validate(r, tps, nil)
}
