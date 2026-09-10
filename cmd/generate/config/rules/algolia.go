package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// Algolia's public Search API key includes these four read-only ACLs.
// "settings" reads index settings; "editSettings" is the write permission.
// https://www.algolia.com/doc/rest-api/search/get-api-key
const algoliaValidateExpr = `let application_id = components["algolia-application-id"]?.secret ?? "";
let r = http.get("https://" + application_id + ".algolia.net/1/keys/" + finding["secret"], {
  "Accept": "application/json",
  "X-Algolia-API-Key": finding["secret"],
  "X-Algolia-Application-Id": application_id
}); let acl = r.json?.acl ?? [];
let public_acls = ["search", "browse", "listIndexes", "settings"];
let has_sensitive_acl = any(acl, {# not in public_acls});
r.status == 200 && has_sensitive_acl ? {
  "result": "valid",
  "analysis": {
    "application_id": application_id,
    "acl": acl,
    "indexes": r.json?.indexes ?? []
  }
} : r.status == 200 && "search" in acl ? {
  "result": "invalid",
  "reason": "Public Algolia Search API key",
  "acl": acl
} : validate.unknown(r)`

const algoliaAnalyzeExpr = `let input = validation.analysis;
let acl = input["acl"] ?? [];
let indexes = input["indexes"] ?? [];
let can_read = filter.intersects(acl, [
  "search", "browse", "listIndexes", "settings", "analytics", "logs", "usage",
  "nluReadProject", "nluReadEntity", "nluReadIntent", "nluReadAnswers"
]);
let can_write = filter.intersects(acl, [
  "addObject", "deleteObject", "deleteIndex", "editSettings",
  "nluWriteProject", "nluWriteEntity", "nluWriteIntent"
]);
{
  "reason": size(acl) == 0 ? "Algolia did not return API key ACLs" :
    !can_read && !can_write ? "Algolia returned no recognized permission grants" : "",
  "identity": {"account": {"id": input["application_id"] ?? ""}},
  "metadata": size(indexes) > 0 ? {
    "acl": acl,
    "indexes": indexes
  } : {
    "acl": acl,
    "all_indexes": true
  },
  "capabilities": analysis.capabilities({"read": can_read, "write": can_write})
}`

func AlgoliaApplicationID() *config.Rule {
	r := config.Rule{
		Description: "Detected an Algolia application ID, used as a component of the algolia-api-key composite rule.",
		ID:          "algolia-application-id",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{10}`, true),
		Keywords:    []string{"algolia"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 2.75 || filter.tokenRatio(finding["secret"]) >= 2.5`,
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
		ID:          "algolia-api-key",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true),
		Keywords:    []string{"algolia"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
		Components: []*config.Component{
			{RuleID: "algolia-application-id"},
		},
		ValidateExpr: algoliaValidateExpr,
		AnalyzeExpr:  algoliaAnalyzeExpr,
	}

	// validate
	tps := utils.GenerateSampleSecrets("algolia", secrets.NewSecretWithEntropy(utils.Hex("32"), 3.5))
	return utils.Validate(r, tps, nil)
}
