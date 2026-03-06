package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "easypost-api-token",
		Description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
		Regex:       regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}\b`),
		Entropy:     2,
		Keywords:    []string{"EZAK"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("EZAK", "EZAK"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{54}`, 2))
	tps = append(tps,
		"EZAK"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{54}`, 2),
		"example.com?t=EZAK"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{54}`, 2)+"&q=1",
	)
	fps := []string{
		// random base64 encoded string
		`...6wqX6fNUXA/rYqRvfQ+EZAKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6...`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}

func EasyPostTestAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "easypost-test-api-token",
		Description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
		Regex:       regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}\b`),
		Entropy:     2,
		Keywords:    []string{"EZTK"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("EZTK", secrets.NewSecretWithEntropy(`EZTK[a-zA-Z0-9]{54}`, 2))
	tps = append(tps, secrets.NewSecretWithEntropy(`EZTK[a-zA-Z0-9]{54}`, 2))
	tps = append(tps,
		"EZTK"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{54}`, 2),
		"example.com?t=EZTK"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{54}`, 2)+"&q=1",
	)
	fps := []string{
		// random base64 encoded string
		`...6wqX6fNUXA/rYqRvfQ+EZTKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6...`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
