package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AlgoliaApplicationID() *config.Rule {
	r := config.Rule{
		Description: "Detected an Algolia application ID, used as a component of the algolia-api-key composite rule.",
		RuleID:      "algolia-application-id",
		Regex:       utils.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{10}`, true),
		Keywords:    []string{"algolia"},
		SkipReport:  true,
	}

	tps := []string{
		`ALGOLIA_APPLICATION_ID=AB12CD34EF`,
		`algoliaAppId: "a1b2c3d4e5"`,
	}
	fps := []string{
		`ALGOLIA_APPLICATION_ID=ABC123`,
		`ALGOLIA_APPLICATION_ID=ABC123456789`,
	}
	return utils.Validate(r, tps, fps)
}

func AlgoliaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
		RuleID:      "algolia-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true),
		Keywords:    []string{"algolia"},
		Components: []*config.Component{
			{RuleID: "algolia-application-id"},
		},
		// Algolia's public Search API key includes these four read-only ACLs.
		// "settings" reads index settings; "editSettings" is the write permission.
		ValidateExpr: `let r = http.get("https://" + (components["algolia-application-id"]?.secret ?? "") + ".algolia.net/1/keys/" + finding["secret"], {
    "Accept": "application/json",
    "X-Algolia-API-Key": finding["secret"],
    "X-Algolia-Application-Id": (components["algolia-application-id"]?.secret ?? "")
  }); let acl = r.json?.acl ?? [];
  let public_acls = ["search", "browse", "listIndexes", "settings"];
  let has_sensitive_acl = any(acl, {# not in public_acls});
  r.status == 200 && has_sensitive_acl ? {
    "result": "valid",
    "acl": acl
  } : r.status == 200 && "search" in acl ? {
    "result": "invalid",
    "reason": "Public Algolia Search API key",
    "acl": acl
  } : validate.unknown(r)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("algolia", secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}
