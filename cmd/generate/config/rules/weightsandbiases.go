package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func WeightsAndBiases() *config.Rule {
	r := config.Rule{
		RuleID:      "weights-and-biases-api-key",
		Description: "Detected a Weights & Biases API Key, which may expose ML experiment tracking and model registry access to unauthorized parties.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"wandb", "weightsandbiases"}, utils.Hex("40"), true),
		Keywords:    []string{"wandb", "weightsandbiases"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("wandb_api_key", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		// Too short
		`wandb_api_key = 872ab943740b34157041da2529fb160d`,
		// All zeros (low entropy)
		`wandb_api_key = 0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func WeightsAndBiasesV1() *config.Rule {
	r := config.Rule{
		RuleID:      "weights-and-biases-api-key-v1",
		Description: "Detected a Weights & Biases v1 API Key (wandb_v1_), which may expose ML experiment tracking and artifact storage to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`wandb_v1_[A-Za-z0-9_]{77}`, true),
		Keywords:    []string{"wandb_v1_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("wandb", "wandb_v1_"+secrets.NewSecret(`[A-Za-z0-9_]{77}`))
	fps := []string{
		// Too short
		`wandb_v1_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpu`,
		// Wrong prefix
		`wandb_v2_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpuofitw2Ko0t7X7CnFU9cOzeUCRUkSdQF4CpXc4`,
	}
	return utils.Validate(r, tps, fps)
}
