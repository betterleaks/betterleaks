package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func SquareAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-access-token",
		Description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
		Regex:       utils2.GenerateUniqueTokenRegex(`(?:EAAA|sq0atp-)[\w-]{22,60}`, false),
		Entropy:     2,
		Keywords:    []string{"sq0atp-", "EAAA"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("square", secrets.NewSecret(`(?:EAAA|sq0atp-)[\w-]{22,60}`))
	tps = append(tps,
		"ARG token=sq0atp-812erere3wewew45678901",                                    // gitleaks:allow
		"ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E", // gitleaks:allow",
	)
	fps := []string{
		`aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00`,
	}
	return utils2.Validate(r, tps, fps)
}

func SquareSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-secret",
		Description: "Square Secret",
		Regex:       utils2.GenerateUniqueTokenRegex(`sq0csp-[\w-]{43}`, false),
		Entropy:     2,
		Keywords:    []string{"sq0csp-"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("square", secrets.NewSecret(`sq0csp-[0-9A-Za-z\\-_]{43}`))
	tps = append(tps,
		`value: "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"`, // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
