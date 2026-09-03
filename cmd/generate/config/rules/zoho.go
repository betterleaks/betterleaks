package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func ZohoOAuthToken() *config.Rule {
	// Access and refresh tokens share this format, and both types are
	// data-center-specific. The fixed US CRM check can prove a matching access
	// token valid, but every non-success remains unknown rather than incorrectly
	// rejecting a refresh token or a credential issued in another region.
	r := config.Rule{
		RuleID:      "zoho-oauth-token.1",
		Confidence:  "high",
		Description: "Zoho OAuth access or refresh token, which may allow access to Zoho APIs or minting of new access tokens.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zoho"}, `1000\.`+utils.Hex("32")+`\.`+utils.Hex("32"), true),
		Keywords:    []string{"zoho"},
		ValidateExpr: `let r = http.get("https://www.zohoapis.com/crm/v8/users?type=CurrentUser", {
    "Authorization": "Zoho-oauthtoken " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"users\"") ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	token := "1000." +
		secrets.NewSecretWithEntropy(`[a-f0-9]{32}`, 3.5) + "." +
		secrets.NewSecretWithEntropy(`[a-f0-9]{32}`, 3.5)
	tps := utils.GenerateSampleSecrets("zoho_oauth", token)
	tps = append(tps,
		`ZOHO_ACCESS_TOKEN=`+token,
		`zoho-refresh-token: "`+token+`"`,
	)
	fps := []string{
		`ACCESS_TOKEN=1000.0123456789abcdef0123456789abcdef.fedcba9876543210fedcba9876543210`,
		`ZOHO_ACCESS_TOKEN=1000.24baa4103269e50e.41fa7dd2b88dd4d4`,
		`ZOHO_CLIENT_ID=1000.9A2N2IKWOJB2F0BZGTJLYAK930GZJG`,
		`ZOHO_ACCESS_TOKEN=1000.00000000000000000000000000000000.00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func ZohoClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "zoho-client-id.1",
		Confidence:  "medium",
		Description: "Zoho OAuth client ID, used as a component of the zoho-client-secret.1 composite rule.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zoho"}, `1000\.`+utils.AlphaNumeric("30"), true),
		Keywords:    []string{"zoho"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(3.0),
	}

	clientID := "1000." + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{30}`, 3.0)
	tps := []string{
		`ZOHO_CLIENT_ID=` + clientID,
		`zoho.client_id: "` + clientID + `"`,
		`response_type=code&zoho_client_id=` + clientID,
	}
	fps := []string{
		`CLIENT_ID=` + clientID,
		`ZOHO_CLIENT_ID=1000.short`,
		`ZOHO_ACCESS_TOKEN=1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4`,
		`ZOHO_CLIENT_ID=1000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}

func ZohoClientSecret() *config.Rule {
	// Zoho clients and client secrets are data-center-specific. A deliberately
	// invalid authorization code proves that a pair reached grant validation,
	// but all other responses remain unknown because invalid_client can also
	// mean that a valid pair was sent to the wrong Zoho accounts region.
	r := config.Rule{
		RuleID:      "zoho-client-secret.1",
		Confidence:  "high",
		Description: "Zoho OAuth client secret, which may allow OAuth client authentication when paired with the associated client ID.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zoho"}, utils.Hex("42"), true),
		Keywords:    []string{"zoho"},
		Components: []*config.Component{
			{RuleID: "zoho-client-id.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.post("https://accounts.zoho.com/oauth/v2/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  }, "client_id=" + strings.urlQueryEscape((components["zoho-client-id.1"]?.secret ?? "")) +
  "&client_secret=" + strings.urlQueryEscape(finding["secret"]) +
  "&grant_type=authorization_code" +
  "&code=betterleaks_invalid_code" +
  "&redirect_uri=https%3A%2F%2Fexample.com%2Fbetterleaks");
  r.status == 200 && (r.json?.error ?? "") == "invalid_code" ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	clientSecret := secrets.NewSecretWithEntropy(`[a-f0-9]{42}`, 3.5)
	tps := []string{
		`ZOHO_CLIENT_SECRET=` + clientSecret,
		`zoho client_secret: "` + clientSecret + `"`,
	}
	fps := []string{
		`CLIENT_SECRET=` + clientSecret,
		`ZOHO_CLIENT_SECRET=ec8970658937efb63d126f73b57b0aa47bf4f2d7d`,
		`ZOHO_CLIENT_SECRET=000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func ZohoZAPIKey() *config.Rule {
	// ZAPI keys authorize a particular Zoho function or webhook. Validation
	// requires that function's provider-owned URL, which cannot be reconstructed
	// safely from the key alone.
	r := config.Rule{
		RuleID:      "zoho-zapi-key.1",
		Confidence:  "high",
		Description: "Zoho ZAPI key, which may authorize CRM functions, extensions, webhooks, or other Zoho APIs.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"zoho"},
			`(?:1001\.`+utils.Hex("32")+`\.`+utils.Hex("32")+`(?:-d)?|1003\.`+utils.Hex("32,64")+`)`,
			true,
		),
		Keywords: []string{"zoho"},
		Filter:   utils.MinEntropy(3.5),
	}

	keyV1 := "1001." +
		secrets.NewSecretWithEntropy(`[a-f0-9]{32}`, 3.5) + "." +
		secrets.NewSecretWithEntropy(`[a-f0-9]{32}`, 3.5)
	keyV3 := "1003." + secrets.NewSecretWithEntropy(`[a-f0-9]{48}`, 3.5)
	tps := []string{
		`ZOHO_ZAPI_KEY=` + keyV1,
		`Zoho-zapikey=` + keyV1 + `-d`,
		`ZOHO_ZAPI_KEY=` + keyV3,
	}
	fps := []string{
		`ZAPI_KEY=` + keyV1,
		`ZOHO_ZAPI_KEY=1001.short`,
		`ZOHO_ZAPI_KEY=1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4`,
		`ZOHO_ZAPI_KEY=1001.00000000000000000000000000000000.00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
