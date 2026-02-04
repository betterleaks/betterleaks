package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AnthropicApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-api-key",
		Description: "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
		Regex:       utils2.GenerateUniqueTokenRegex(`sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`, false),
		Keywords: []string{
			"sk-ant-api03",
		},
	}

	// validate
	tps := []string{
		// Valid API key example
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
		// Generate additional random test keys
		utils2.GenerateSampleSecret("anthropic", "sk-ant-api03-"+secrets.NewSecret(utils2.AlphaNumericExtendedShort("93"))+"AA"),
	}

	fps := []string{
		// Too short key (missing characters)
		"sk-ant-api03-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA",
		// Wrong suffix
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB",
		// Wrong prefix (admin key, not API key)
		"sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
	}

	return utils2.Validate(r, tps, fps)
}

func AnthropicAdminApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-admin-api-key",
		Description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
		Regex:       utils2.GenerateUniqueTokenRegex(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, false),
		Keywords: []string{
			"sk-ant-admin01",
		},
	}

	// validate
	tps := []string{
		// Valid admin key example
		"sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA",
		// Generate additional random test keys
		utils2.GenerateSampleSecret("anthropic", "sk-ant-admin01-"+secrets.NewSecret(utils2.AlphaNumericExtendedShort("93"))+"AA"),
	}

	fps := []string{
		// Too short key (missing characters)
		"sk-ant-admin01-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA",
		// Wrong suffix
		"sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB",
		// Wrong prefix (API key, not admin key)
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
	}

	return utils2.Validate(r, tps, fps)
}
