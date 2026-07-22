package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SelectelStaticToken() *config.Rule {
	r := config.Rule{
		RuleID:      "selectel-static-token",
		Description: "Detected a Selectel Static API Token, which may expose access to Selectel cloud services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"selectel"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"selectel"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("selectel", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`selectel_region = "ru-1"`,
		`selectel = "example"`,
	}
	return utils.Validate(r, tps, fps)
}

func VKServiceToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vk-service-token",
		Description: "Detected a VK (VKontakte) Service or Access Token, potentially exposing access to VK API and user data.",
		Regex:       utils.GenerateUniqueTokenRegex(`vk1\.a\.[a-z0-9_-]{50,150}`, true),
		Keywords:    []string{"vk1.a."},
		Entropy:     3.5,
	}

	tps := []string{
		utils.GenerateSampleSecret("vk", "vk1.a."+secrets.NewSecretWithEntropy(`[a-z0-9_-]{80}`, 3.5)),
	}
	fps := []string{
		`vk_token = "vk1.b.abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901"`,
		`vk_token = "vk1.a.tooshort"`,
	}
	return utils.Validate(r, tps, fps)
}

func SberGigaChatKey() *config.Rule {
	r := config.Rule{
		RuleID:      "sber-gigachat-key",
		Description: "Detected a Sber GigaChat API Key, which could allow unauthorized access to Sber AI services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"gigachat", "sber"}, `[a-z0-9]{50,100}`, true),
		Keywords:    []string{"gigachat", "sber"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("gigachat", secrets.NewSecretWithEntropy(`[a-z0-9]{50,100}`, 3.5))
	fps := []string{
		`sber_bank = "123456"`,
		`gigachat_model = "GigaChat-Pro"`,
	}
	return utils.Validate(r, tps, fps)
}
