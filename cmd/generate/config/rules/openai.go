package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

// commonValidateCEL is shared by project, service-account, and admin key types.
// All current OpenAI key types authenticate via Bearer token against the same endpoint.
const commonValidateCEL = `cel.bind(r,
  http.get("https://api.openai.com/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.json.?object.orValue("") == "list" ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`

// openaiSecretPattern matches the variable-length base64url payload common to
// proj, svcacct, and admin keys (74, 58, or 20 chars before and after the
// T3BlbkFJ sentinel).
const openaiSecretPattern = `(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})`

func OpenAIProjectApiKey() *config.Rule {
	r := config.Rule{
		RuleID:      "openai-project-api-key",
		Description: "Found an OpenAI Project API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-proj-`+openaiSecretPattern, false),
		Entropy:     3,
		Keywords: []string{
			"sk-proj-",
		},
		ValidateCEL: commonValidateCEL,
	}

	tps := []string{
		// Legacy format project keys (sk- prefix, 20+20)
		utils.GenerateSampleSecret("openaiProjectKey", "sk-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)),
	}
	tps = utils.GenerateSampleSecrets("openaiProjectKey", "sk-proj-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3))
	tps = append(tps, utils.GenerateSampleSecrets("openaiProjectKey", "sk-proj-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("openaiProjectKey", "sk-proj-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3))...)
	tps = append(tps, []string{
		`"client = OpenAI(api_key=\"sk-proj-1AXfKYubvBH1LYyObyxST3BlbkFJSXJZjpk2sZk3POtOlPna\")\n",`,
		"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",
		"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",
		"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",
	}...)

	return utils.Validate(r, tps, nil)
}

func OpenAIServiceAccountApiKey() *config.Rule {
	r := config.Rule{
		RuleID:      "openai-service-account-api-key",
		Description: "Found an OpenAI Service Account API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-svcacct-`+openaiSecretPattern, false),
		Entropy:     3,
		Keywords: []string{
			"sk-svcacct-",
		},
		ValidateCEL: commonValidateCEL,
	}

	tps := []string{
		"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",
		"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",
		"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",
	}
	tps = append(tps, utils.GenerateSampleSecrets("openaiSvcAcctKey", "sk-svcacct-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("openaiSvcAcctKey", "sk-svcacct-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("openaiSvcAcctKey", "sk-svcacct-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3))...)

	return utils.Validate(r, tps, nil)
}

func OpenAIAdminApiKey() *config.Rule {
	r := config.Rule{
		RuleID:      "openai-admin-api-key",
		Description: "Detected an OpenAI Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-admin-`+openaiSecretPattern, false),
		Entropy:     3,
		Keywords: []string{
			"sk-admin-",
		},
		ValidateCEL: commonValidateCEL,
	}

	tps := []string{
		"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",
		"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",
		"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",
	}
	tps = append(tps, utils.GenerateSampleSecrets("openaiAdminKey", "sk-admin-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("openaiAdminKey", "sk-admin-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("58"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("openaiAdminKey", "sk-admin-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("20"), 3))...)

	return utils.Validate(r, tps, nil)
}

func OpenAILegacyApiKey() *config.Rule {
	r := config.Rule{
		RuleID:      "openai-legacy-api-key",
		Description: "Found a legacy OpenAI API Key (sk-...T3BlbkFJ... format), which may compromise AI service integrations and expose sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Entropy:     3,
		Keywords: []string{
			"T3BlbkFJ",
		},
		ValidateCEL: commonValidateCEL,
	}

	tps := []string{
		utils.GenerateSampleSecret("openaiLegacyKey", "sk-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)),
	}
	tps = append(tps, utils.GenerateSampleSecrets("openaiLegacyKey", "sk-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))...)

	fps := []string{
		// A typed key (sk-proj-) should NOT match the legacy rule
		"sk-proj-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3),
		// A service account key should NOT match either
		"sk-svcacct-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3),
		// An admin key should NOT match the legacy rule
		"sk-admin-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("74"), 3),
	}

	return utils.Validate(r, tps, fps)
}
