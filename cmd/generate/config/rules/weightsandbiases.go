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
		ValidateCEL: `cel.bind(r,
  http.post("https://api.wandb.ai/graphql", {
    "Authorization": "Basic " + base64.encode(bytes("api:" + secret)),
    "Content-Type": "application/json"
  }, "{\"query\":\"query { viewer { email username } }\"}"),
  r.status == 200 && r.body.contains("\"username\"") ? {
    "result": "valid",
    "email": r.json.?data.?viewer.?email.orValue(""),
    "username": r.json.?data.?viewer.?username.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("wandb_api_key", secrets.NewSecretWithEntropy(utils.Hex("40"), 3.5))
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
		ValidateCEL: `cel.bind(r,
  http.post("https://api.wandb.ai/graphql", {
    "Authorization": "Basic " + base64.encode(bytes("api:" + secret)),
    "Content-Type": "application/json"
  }, "{\"query\":\"query { viewer { email username } }\"}"),
  r.status == 200 && r.body.contains("\"username\"") ? {
    "result": "valid",
    "email": r.json.?data.?viewer.?email.orValue(""),
    "username": r.json.?data.?viewer.?username.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("wandb", "wandb_v1_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_]{77}`, 3.5))
	fps := []string{
		// Too short
		`wandb_v1_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpu`,
		// Wrong prefix
		`wandb_v2_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpuofitw2Ko0t7X7CnFU9cOzeUCRUkSdQF4CpXc4`,
	}
	return utils.Validate(r, tps, fps)
}
