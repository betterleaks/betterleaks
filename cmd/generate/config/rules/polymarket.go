package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func PolymarketAPISecret() *config.Rule {
	r := config.Rule{
		RuleID:      "polymarket-api-secret",
		Confidence:  "medium",
		Description: "Discovered a Polymarket API secret, which could be used to sign authenticated requests to the Polymarket L2 API.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"poly.{0,20}secret"}, `[a-zA-Z0-9+/]{40,}={0,2}`, false),
		Keywords:    []string{"poly"},
		SkipReport:  true,
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("poly_secret", secrets.NewSecretWithEntropy(`[a-zA-Z0-9+/]{40}`, 4))
	tps = append(tps, utils.GenerateSampleSecrets("poly_secret", secrets.NewSecretWithEntropy(`[a-zA-Z0-9+/]{44}`, 4)+"==")...)
	return utils.Validate(r, tps, nil)
}

func PolymarketPassphrase() *config.Rule {
	r := config.Rule{
		RuleID:      "polymarket-passphrase",
		Confidence:  "medium",
		Description: "Found a Polymarket API passphrase, used as a component of authenticated Polymarket API requests.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"poly.{0,20}passphrase"}, `[a-zA-Z0-9_]{8,128}`, false),
		Keywords:    []string{"poly"},
		SkipReport:  true,
	}

	tps := utils.GenerateSampleSecrets("poly_passphrase", secrets.NewSecret(`[a-zA-Z0-9_]{12}`))
	tps = append(tps, utils.GenerateSampleSecrets("poly_passphrase", secrets.NewSecret(`[a-zA-Z0-9_]{64}`))...)
	return utils.Validate(r, tps, nil)
}

func PolymarketAddress() *config.Rule {
	r := config.Rule{
		RuleID:      "polymarket-address",
		Confidence:  "medium",
		Description: "Found a Polymarket wallet address, used as a component of authenticated Polymarket API requests.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"poly.{0,20}address"}, `0x[a-fA-F0-9]{40}`, false),
		Keywords:    []string{"poly"},
		SkipReport:  true,
	}

	tps := utils.GenerateSampleSecrets("poly_address", "0x"+secrets.NewSecret(`[a-fA-F0-9]{40}`))
	return utils.Validate(r, tps, nil)
}

func PolymarketAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "polymarket-api-key",
		Confidence:  "high",
		Description: "Identified a Polymarket API key, potentially compromising access to the Polymarket trading platform.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"poly.{0,20}key"}, utils.Hex8_4_4_4_12(), false),
		Keywords:    []string{"poly"},
		Components: []*config.Component{
			{
				RuleID: "polymarket-api-secret",
				Within: "20L",
			},
			{
				RuleID: "polymarket-passphrase",
				Within: "20L",
			},
		},
		ValidateExpr: `let ts = time.nowUnix(); (let sig = crypto.hmacSha256(
      base64.decode((components["polymarket-api-secret"]?.secret ?? "")),
      bytes(ts + "GET" + "/data/orders")
    ); (let r = http.get("https://clob.polymarket.com/data/orders", {
        "POLY_BUILDER_API_KEY": finding["secret"],
        "POLY_BUILDER_PASSPHRASE": (components["polymarket-passphrase"]?.secret ?? ""),
        "POLY_BUILDER_TIMESTAMP": ts,
        "POLY_BUILDER_SIGNATURE": replace(replace(base64.encode(sig), "+", "-"), "/", "_")
      }); r.status == 200 ? {
        "result": "valid"
      } : r.status in [401, 403] ? {
        "result": "invalid",
        "reason": "Unauthorized"
      } : validate.unknown(r)))`,
		Filter: `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("poly_key", secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3))
	return utils.Validate(r, tps, nil)
}

func PolymarketPrivateKey() *config.Rule {
	r := config.Rule{
		RuleID:      "polymarket-private-key",
		Confidence:  "medium",
		Description: "Discovered a Polymarket private key, which could allow unauthorized trading and fund transfers.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"poly.{0,20}private.{0,20}key"}, `0x[a-fA-F0-9]{64}`, false),
		Keywords:    []string{"poly"},
		Filter:      `entropy(finding["secret"]) <= 3.5`,
	}

	tps := utils.GenerateSampleSecrets("poly_private_key", "0x"+secrets.NewSecretWithEntropy(`[a-fA-F0-9]{64}`, 3.5))
	return utils.Validate(r, tps, nil)
}
