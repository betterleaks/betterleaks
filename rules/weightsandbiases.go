package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "weights-and-biases-api-key",
	Confidence:  "medium",
	Description: "Detected a Weights & Biases API Key, which may expose ML experiment tracking and model registry access to unauthorized parties.",
	Regex:       rulebuilder.Assignment([]string{"wandb", "weightsandbiases"}, `(?i)`+rulebuilder.Hex("40")),
	Keywords:    []string{"wandb", "weightsandbiases"},
	ValidateExpr: `let r = http.post("https://api.wandb.ai/graphql", {
    "Authorization": "Basic " + base64.encode(bytes("api:" + finding["secret"])),
    "Content-Type": "application/json"
  }, "{\"query\":\"query { viewer { email username } }\"}"); r.status == 200 && (r.body contains "\"username\"") ? {
    "result": "valid",
    "metadata": {"email": (r.json?.data?.viewer?.email ?? ""), "username": (r.json?.data?.viewer?.username ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `wandb_api_keyToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.NoMatch("Too short", "wandb_api_key = 872ab943740b34157041da2529fb160d"),
		rulebuilder.NoMatch("All zeros (low entropy)", "wandb_api_key = 0000000000000000000000000000000000000000"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "weights-and-biases-api-key-v1",
	Confidence:  "high",
	Description: "Detected a Weights & Biases v1 API Key (wandb_v1_), which may expose ML experiment tracking and artifact storage to unauthorized access.",
	Regex:       rulebuilder.Token(`(?i)wandb_v1_[A-Za-z0-9_]{77}`),
	Keywords:    []string{"wandb_v1_"},
	ValidateExpr: `let r = http.post("https://api.wandb.ai/graphql", {
    "Authorization": "Basic " + base64.encode(bytes("api:" + finding["secret"])),
    "Content-Type": "application/json"
  }, "{\"query\":\"query { viewer { email username } }\"}"); r.status == 200 && (r.body contains "\"username\"") ? {
    "result": "valid",
    "metadata": {"email": (r.json?.data?.viewer?.email ?? ""), "username": (r.json?.data?.viewer?.username ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `wandbToken = "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"`, "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"),
		rulebuilder.NoMatch("Too short", "wandb_v1_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpu"),
		rulebuilder.NoMatch("Wrong prefix", "wandb_v2_PP8ss3eYn15faGat7OceNWnAZee_COKJ7riO0Bpuofitw2Ko0t7X7CnFU9cOzeUCRUkSdQF4CpXc4"),
	},
})
