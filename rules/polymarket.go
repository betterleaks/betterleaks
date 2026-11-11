package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "polymarket-api-secret",
	Confidence:  "medium",
	Description: "Discovered a Polymarket API secret, which could be used to sign authenticated requests to the Polymarket L2 API.",
	Regex:       Assignment([]string{"poly.{0,20}secret"}, `[a-zA-Z0-9+/]{40,}={0,2}`),
	Keywords:    []string{"poly"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "poly_secret assignment",
			Mode:  "match",
			Input: `poly_secretToken = "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"`,
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"},
			},
		},
		{
			Name:  "poly_secret assignment 2",
			Mode:  "match",
			Input: `poly_secretToken = "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81=="`,
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81=="},
			},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "polymarket-passphrase",
	Confidence:  "medium",
	Description: "Found a Polymarket API passphrase, used as a component of authenticated Polymarket API requests.",
	Regex:       Assignment([]string{"poly.{0,20}passphrase"}, `[a-zA-Z0-9_]{8,128}`),
	Keywords:    []string{"poly"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "poly_passphrase assignment",
			Mode:  "match",
			Input: `poly_passphraseToken = "eoTtDxpQ4FWY"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoTtDxpQ4FWY"},
			},
		},
		{
			Name:  "poly_passphrase assignment 2",
			Mode:  "match",
			Input: `poly_passphraseToken = "eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmOeW3zf7CIYVs0s_gjscR7rfMPh3yeQfu3"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmOeW3zf7CIYVs0s_gjscR7rfMPh3yeQfu3"},
			},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "polymarket-address",
	Confidence:  "medium",
	Description: "Found a Polymarket wallet address, used as a component of authenticated Polymarket API requests.",
	Regex:       Assignment([]string{"poly.{0,20}address"}, `0x[a-fA-F0-9]{40}`),
	Keywords:    []string{"poly"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "poly_address assignment",
			Mode:  "match",
			Input: `poly_addressToken = "0x1193D476664BABC675dad0AA9B5629Bc51d01b14"`,
			Expect: []config.ExpectedFinding{
				{Secret: "0x1193D476664BABC675dad0AA9B5629Bc51d01b14"},
			},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "polymarket-api-key",
	Confidence:  "high",
	Description: "Identified a Polymarket API key, potentially compromising access to the Polymarket trading platform.",
	Regex:       Assignment([]string{"poly.{0,20}key"}, Hex8_4_4_4_12()),
	Keywords:    []string{"poly"},
	Components: []config.Component{
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
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "poly_key assignment",
			Input: "poly_keyToken = \"1f7b169c-846f-218a-b552-fa82fbf86758\"\npoly_secretToken = \"VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG\"\npoly_passphraseToken = \"eoTtDxpQ4FWY\"",
			Expect: []config.ExpectedFinding{
				{Secret: "1f7b169c-846f-218a-b552-fa82fbf86758", ComponentSets: []map[string]string{{"polymarket-api-secret": "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG", "polymarket-passphrase": "eoTtDxpQ4FWY"}}},
			},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "polymarket-private-key",
	Confidence:  "medium",
	Description: "Discovered a Polymarket private key, which could allow unauthorized trading and fund transfers.",
	Regex:       Assignment([]string{"poly.{0,20}private.{0,20}key"}, `0x[a-fA-F0-9]{64}`),
	Keywords:    []string{"poly"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("poly_private_key assignment", `poly_private_keyToken = "0x1193D476664BABC675dad0AA9B5629Bc51d01b14b6aFDFa05FF7d5c72AB1F452"`, "0x1193D476664BABC675dad0AA9B5629Bc51d01b14b6aFDFa05FF7d5c72AB1F452"),
	},
})
