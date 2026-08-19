package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LangfusePublicKey() *config.Rule {
	r := config.Rule{
		RuleID:      "langfuse-public-key.1",
		Confidence:  "high",
		Description: "Langfuse public key, used as a component of the Langfuse secret-key composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`pk-lf-`+uuidPattern(), false),
		Keywords:    []string{"pk-lf-"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(3.0),
	}

	publicKey := "pk-lf-" + randomUUID()
	tps := []string{
		`LANGFUSE_PUBLIC_KEY=` + publicKey,
	}
	fps := []string{
		`LANGFUSE_PUBLIC_KEY=pk-lf-00000000-0000-0000-0000-000000000000`,
		`LANGFUSE_PUBLIC_KEY=pk-lf-short`,
	}
	return utils.Validate(r, tps, fps)
}

func LangfuseSecretKey() *config.Rule {
	// Langfuse also supports several cloud regions and self-hosted instances.
	// The EU cloud request can prove a matching pair valid; non-success remains
	// unknown rather than rejecting credentials issued for another host.
	r := config.Rule{
		RuleID:      "langfuse-secret-key.1",
		Confidence:  "high",
		Description: "Langfuse secret key, which authenticates project API access when paired with its public key.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-lf-`+uuidPattern(), false),
		Keywords:    []string{"sk-lf-"},
		Components: []*config.Component{
			{RuleID: "langfuse-public-key.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.get("https://cloud.langfuse.com/api/public/projects", {
    "Authorization": "Basic " + base64.encode(bytes((components["langfuse-public-key.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	secretKey := "sk-lf-" + randomUUID()
	tps := []string{
		`LANGFUSE_SECRET_KEY=` + secretKey,
	}
	fps := []string{
		`LANGFUSE_SECRET_KEY=sk-lf-00000000-0000-0000-0000-000000000000`,
		`LANGFUSE_SECRET_KEY=sk-lf-short`,
	}
	return utils.Validate(r, tps, fps)
}

func uuidPattern() string {
	return utils.Hex("8") + `-` + utils.Hex("4") + `-` + utils.Hex("4") + `-` + utils.Hex("4") + `-` + utils.Hex("12")
}

func randomUUID() string {
	return secrets.NewSecretWithEntropy(`[a-f0-9]{8}`, 2.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{12}`, 2.5)
}
