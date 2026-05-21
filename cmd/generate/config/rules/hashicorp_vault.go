package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func VaultServiceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "vault-service-token",
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`, false),
		Keywords:    []string{"hvs.", "s."},
		Filter: `entropy(finding["secret"]) <= 3.5
|| matchesAny(finding["secret"], [r"""s\.[A-Za-z]{24}"""])`,
	}

	// validate
	tps := []string{
		// Old
		utils.GenerateSampleSecret("vault", secrets.NewSecretWithEntropy(`s\.[0-9][a-zA-Z0-9]{23}`, 3.5)),
		`token: s.ZC9Ecf4M5g9o34Q6RkzGsj0z`,
		// New
		utils.GenerateSampleSecret("vault", secrets.NewSecretWithEntropy(`hvs\.[0-9][\w\-]{89}`, 3.5)),
		`-vaultToken hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg"`, // longer than 100 chars
	}

	fps := []string{
		// Old
		`  credentials: new AWS.SharedIniFileCredentials({ profile: '<YOUR_PROFILE>' })`,                              // word boundary start
		`INFO 4 --- [           main] o.s.b.f.s.DefaultListableBeanFactory     : Overriding bean definition for bean`, // word boundary end
		`s.xxxxxxxxxxxxxxxxxxxxxxxx`,        // low entropy
		`s.THISSTRINGISALLUPPERCASE`,        // uppercase
		`s.thisstringisalllowercase`,        // lowercase
		`s.AcceptanceTimeoutSeconds `,       // pascal-case
		`s.makeKubeConfigController = args`, // camel-case
		// New
		`hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func VaultBatchToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "vault-batch-token",
		Description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex(`hvb\.[\w-]{138,300}`, false),
		Keywords:    []string{"hvb."},
		Filter: `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("vault", "hvb."+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("138"), 4))
	tps = append(tps, `hvb.AAAAAQJgxDgqsGNorpoOR7hPZ5SU-ynBvCl764jyRP_fnX7WvkdkDzGjbLNGdPdtlY33Als2P36yDZueqzfdGw9RsaTeaYXSH7E4RYSWuRoQ9YRKIw8o7mDDY2ZcT3KOB7RwtW1w1FN2eDqcy_sbCjXPaM1iBVH-mqMSYRmRd2nb5D1SJPeBzIYRqSglLc31wUGN7xEzyrKUczqOKsIcybQA`) // gitleaks:allow
	return utils.Validate(r, tps, nil)
}
