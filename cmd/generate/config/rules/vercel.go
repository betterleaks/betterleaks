package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func VercelAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-api-token",
		Description: "Detected a Vercel API Token, which may expose deployment and serverless infrastructure to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"vercel"}, `[A-Z0-9]{24}`, true),
		Keywords:    []string{"vercel"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.vercel.com/v2/user", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains("\"user\"") && r.body.contains("\"email\"") ? {
    "result": "valid",
    "email": r.json.?user.?email.orValue(""),
    "username": r.json.?user.?username.orValue(""),
    "user_id": r.json.?user.?id.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", secrets.NewSecretWithEntropy(`[A-Z0-9]{24}`, 3.5))
	tps = append(tps,
		`vercel-key = DdZV6ZDZW6Vpl7n7JqtrCE5i`,
		`vercel_token = zyMBA1qVEMAf4UNNZtCAbg6u`,
		`vercel_api_key = MTg0AW799OY1HmyDdn84or3C`,
		`vercel_secret = A7n9Xfp3tBz7D0XpOTMWpiOM`,
	)
	fps := []string{
		// Too short
		`vercel_key = DdZV6ZDZW6Vpl7n7Jq`,
		// All same chars (low entropy)
		`vercel_key = AAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelPersonalAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-personal-access-token",
		Description: "Detected a Vercel Personal Access Token (vcp_), which may expose full account and deployment management capabilities.",
		Regex:       utils.GenerateUniqueTokenRegex(`vcp_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vcp_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.vercel.com/v2/user", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains("\"user\"") && r.body.contains("\"email\"") ? {
    "result": "valid",
    "email": r.json.?user.?email.orValue(""),
    "username": r.json.?user.?username.orValue(""),
    "user_id": r.json.?user.?id.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vcp_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{56}`, 3.5))
	tps = append(tps,
		`vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
		`vercel_access_token=vcp_4mcjwVDwqtVCVGWCcxRjdzGpkGZ3NkwXZv8ktcoQ0EG0dnjpMP1Rzi71`,
	)
	fps := []string{
		// Too short
		`vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe`,
		// Wrong prefix
		`vct_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelIntegrationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-integration-token",
		Description: "Detected a Vercel Integration Token (vci_), which may allow third-party service integrations to act on behalf of users.",
		Regex:       utils.GenerateUniqueTokenRegex(`vci_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vci_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.vercel.com/v2/user", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains("\"user\"") ? {
    "result": "valid",
    "email": r.json.?user.?email.orValue(""),
    "username": r.json.?user.?username.orValue(""),
    "user_id": r.json.?user.?id.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vci_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{56}`, 3.5))
	tps = append(tps,
		`Vercel Integration Token: vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
	)
	fps := []string{
		// Too short
		`vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe`,
		// Wrong prefix
		`vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAppAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-app-access-token",
		Description: "Detected a Vercel App Access Token (vca_), which may allow Sign in with Vercel apps to access user resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`vca_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vca_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.post("https://api.vercel.com/login/oauth/userinfo", {
    "Authorization": "Bearer " + secret
  }, ""),
  r.status == 200 && r.body.contains("\"sub\"") ? {
    "result": "valid",
    "email": r.json.?email.orValue(""),
    "user_id": r.json.?sub.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vca_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{56}`, 3.5))
	tps = append(tps,
		`vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	)
	fps := []string{
		// Too short
		`vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t`,
		// Wrong prefix
		`vcb_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAppRefreshToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-app-refresh-token",
		Description: "Detected a Vercel App Refresh Token (vcr_), which may allow persistent unauthorized access through token refresh flows.",
		Regex:       utils.GenerateUniqueTokenRegex(`vcr_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vcr_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.post("https://api.vercel.com/login/oauth/token/introspect", {
    "Content-Type": "application/x-www-form-urlencoded"
  }, "token=" + secret),
  r.status == 200 && r.body.contains("\"active\":true") ? {
    "result": "valid"
  } : r.status == 200 && r.body.contains("\"active\":false") ? {
    "result": "invalid",
    "reason": "Token inactive"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vcr_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{56}`, 3.5))
	tps = append(tps,
		`vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	)
	fps := []string{
		// Too short
		`vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t`,
		// Wrong prefix
		`vcp_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAIGatewayKey() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-ai-gateway-key",
		Description: "Detected a Vercel AI Gateway API Key (vck_), which may expose AI model routing and gateway access to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`vck_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vck_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.post("https://ai-gateway.vercel.sh/v1/chat/completions", {
    "Authorization": "Bearer " + secret,
    "Content-Type": "application/json"
  }, "{\"model\":\"openai/gpt-3.5-turbo\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":1}"),
  r.status in [200, 403] ? {
    "result": "valid"
  } : r.status in [401] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vck_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{56}`, 3.5))
	tps = append(tps,
		`vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K`,
	)
	fps := []string{
		// Too short
		`vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4t`,
		// Wrong prefix
		`vcp_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K`,
	}
	return utils.Validate(r, tps, fps)
}
