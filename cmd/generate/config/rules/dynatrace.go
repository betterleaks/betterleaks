package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func Dynatrace() *config.Rule {
	r := config.Rule{
		RuleID:      "dynatrace-api-token",
		Description: "Identified a Dynatrace API token, which may grant unauthorized access to a Dynatrace tenant's monitoring data, configuration, and APIs.",
		Regex:       regexp.MustCompile(`\bdt0[a-z][0-9]{2}\.[A-Za-z0-9\-]{8,128}\.[A-Z0-9]{64}\b`),
		Keywords:    []string{"dt0"},
		Filter:      `entropy(finding["secret"]) <= 4.0`,
	}

	tps := utils.GenerateSampleSecrets("dynatrace", "dt0c01."+secrets.NewSecretWithEntropy(`[A-Z0-9]{24}`, 4)+"."+secrets.NewSecretWithEntropy(`[A-Z0-9]{64}`, 4))
	tps = append(tps, utils.GenerateSampleSecrets("dynatrace", "dt0s16."+secrets.NewSecret(`[A-Z0-9]{8}`)+"."+secrets.NewSecretWithEntropy(`[A-Z0-9]{64}`, 4))...)
	return utils.Validate(r, tps, nil)
}

func DynatraceVerified() *config.Rule {
	r := config.Rule{
		RuleID:      "dynatrace-api-token-verified",
		Description: "Identified a Dynatrace API token together with its tenant URL, which may grant unauthorized access to that tenant's monitoring data, configuration, and APIs.",
		Regex:       regexp.MustCompile(`\bdt0[a-z][0-9]{2}\.[A-Za-z0-9\-]{8,128}\.[A-Z0-9]{64}\b`),
		Keywords:    []string{"dt0"},
		Specificity: 200,
		RequiredRules: []*config.Required{
			{RuleID: "dynatrace-tenant-url"},
		},
		ValidateExpr: `let tenant = captures["dynatrace-tenant-url"];
let host = replace(replace(tenant, ".apps.dynatrace.com", ".live.dynatrace.com"), ".apps.", ".");
let r = http.post("https://" + host + "/api/v2/apiTokens/lookup", {
    "Authorization": "Api-Token " + finding["secret"],
    "Accept": "application/json; charset=utf-8",
    "Content-Type": "application/json; charset=utf-8"
  }, "{\"token\":" + json.string(finding["secret"]) + "}"); r.status in [200, 403] ? {
    "result": "valid",
    "tenant": tenant
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized",
    "tenant": tenant
  } : validate.unknown(r)`,
		Filter: `entropy(finding["secret"]) <= 4.0`,
	}

	tps := utils.GenerateSampleSecrets("dynatrace", "dt0c01."+secrets.NewSecretWithEntropy(`[A-Z0-9]{24}`, 4)+"."+secrets.NewSecretWithEntropy(`[A-Z0-9]{64}`, 4))
	tps = append(tps, utils.GenerateSampleSecrets("dynatrace", "dt0s16."+secrets.NewSecret(`[A-Z0-9]{8}`)+"."+secrets.NewSecretWithEntropy(`[A-Z0-9]{64}`, 4))...)
	return utils.Validate(r, tps, nil)
}

func DynatraceTenantURL() *config.Rule {
	r := config.Rule{
		RuleID:      "dynatrace-tenant-url",
		Description: "Detected a Dynatrace tenant URL, used as a component of the dynatrace-api-token-verified composite rule.",
		Regex:       regexp.MustCompile(`\b([a-z0-9-]+\.(?:live\.dynatrace|apps\.dynatrace|(?:dev|sprint)\.dynatracelabs|(?:dev|sprint)\.apps\.dynatracelabs)\.com)\b`),
		Keywords:    []string{"dynatrace"},
		SkipReport:  true,
	}

	tps := []string{
		secrets.NewSecret(`[a-z0-9]{8}`) + ".live.dynatrace.com",
		secrets.NewSecret(`[a-z0-9]{8}`) + ".apps.dynatrace.com",
		secrets.NewSecret(`[a-z0-9]{8}`) + ".dev.dynatracelabs.com",
		secrets.NewSecret(`[a-z0-9]{8}`) + ".dev.apps.dynatracelabs.com",
		secrets.NewSecret(`[a-z0-9]{8}`) + ".sprint.dynatracelabs.com",
		secrets.NewSecret(`[a-z0-9]{8}`) + ".sprint.apps.dynatracelabs.com",
	}
	return utils.Validate(r, tps, nil)
}
