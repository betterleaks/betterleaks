package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DevinPersonalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "devin-personal-api-key",
		Description: "Detected a Cognition Devin personal API key, which may expose Devin sessions and user data.",
		Regex:       utils.GenerateUniqueTokenRegex(`apk_user_[A-Za-z0-9+/]{120,180}={0,2}`, false),
		Keywords:    []string{"apk_user_"},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.devin.ai/v1/sessions?limit=1", "r.body.contains(\"\\\"sessions\\\"\")"),
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6MjUwZjRhNzc2ZDEyNGVlMTk0NDk5OGNhNmRmNjBiY2I=`,
		`DEVIN_API_KEY=apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6YTYzNWU0MTA3M2VkNDU3OGFmZDFhMjAxZDhkMjNkODg=`,
	}
	return utils.Validate(r, tps, nil)
}

func DevinServiceAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "devin-service-api-key",
		Description: "Detected a Cognition Devin service API key, which may expose Devin sessions and organization access.",
		Regex:       utils.GenerateUniqueTokenRegex(`apk_[A-Za-z0-9+/]{80,100}={0,2}`, false),
		Keywords:    []string{"apk_"},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.devin.ai/v1/sessions?limit=1", "r.body.contains(\"\\\"sessions\\\"\")"),
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOjM0MTU3ZWU4NTZiMjRkMjI5MDYwNzAxOGJmMGEyYzU0`,
		`DEVIN_API_KEY=apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOmFjMWE2YWEwZjhjYzQ0OGNiY2Q5ZDJlOTI5MGEyN2Jh`,
	}
	fps := []string{
		`apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6MjUwZjRhNzc2ZDEyNGVlMTk0NDk5OGNhNmRmNjBiY2I=`,
	}
	return utils.Validate(r, tps, fps)
}

func DevinServiceUserToken() *config.Rule {
	r := config.Rule{
		RuleID:      "devin-service-user-token",
		Description: "Detected a Cognition Devin service user token, which may expose Devin service user access.",
		Regex:       utils.GenerateUniqueTokenRegex(`cog_[a-z2-7]{52}`, false),
		Keywords:    []string{"cog_"},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.devin.ai/v3/self", "r.body.contains(\"\\\"principal_type\\\"\") || r.body.contains(\"\\\"service_user_id\\\"\")"),
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`cog_l5osrifmypvazi4j3yko52gj6jfj7qprsmy4lrcf27jas4szffha`,
		`DEVIN_API_KEY=cog_uv23fh6fc5kpaxdqif7hyvmzslnbmwriqita7cqkbb4rpaixnleq`,
	}
	return utils.Validate(r, tps, nil)
}
