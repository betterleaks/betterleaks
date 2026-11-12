package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
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
  "metadata": {"acl": acl}
} : validate.unknown(r)`

const algoliaAnalyzeExpr = `let input = validation.analysis;
let acl = input["acl"] ?? [];
let indexes = input["indexes"] ?? [];
let can_read = intersects(acl, [
  "search", "browse", "listIndexes", "settings", "analytics", "logs", "usage",
  "nluReadProject", "nluReadEntity", "nluReadIntent", "nluReadAnswers"
]);
let can_write = intersects(acl, [
  "addObject", "deleteObject", "deleteIndex", "editSettings",
  "nluWriteProject", "nluWriteEntity", "nluWriteIntent"
]);
{
  "reason": len(acl) == 0 ? "Algolia did not return API key ACLs" :
    !can_read && !can_write ? "Algolia returned no recognized permission grants" : "",
  "identity": {"account": {"id": input["application_id"] ?? ""}},
  "metadata": len(indexes) > 0 ? {
    "acl": acl,
    "indexes": indexes
  } : {
    "acl": acl,
    "all_indexes": true
  },
  "capabilities": analysis.capabilities({"read": can_read, "write": can_write})
}`

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected an Algolia application ID, used as a component of the algolia-api-key composite rule.",
	ID:          "algolia-application-id",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"algolia"}, `(?i)[a-z0-9]{10}`),
	Keywords:    []string{"algolia"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 2.75 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "ALGOLIA_APPLICATION_ID=AB12CD34EF", "AB12CD34EF"),
		rulebuilder.MatchComponent("true positive 2", `algoliaAppId: "a1b2c3d4e5"`, "a1b2c3d4e5"),
		rulebuilder.NoMatchComponent("false positive 1", "ALGOLIA_APPLICATION_ID=ABC123"),
		rulebuilder.NoMatchComponent("false positive 2", "ALGOLIA_APPLICATION_ID=ABC123456789"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
	ID:          "algolia-api-key",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"algolia"}, `(?i)[a-z0-9]{32}`),
	Keywords:    []string{"algolia"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Components: []config.Component{
		{RuleID: "algolia-application-id"},
	},
	ValidateExpr: algoliaValidateExpr,
	AnalyzeExpr:  algoliaAnalyzeExpr,
	Tests: []config.RuleTest{
		{
			Name:  "assignment",
			Input: "algoliaToken = \"bf5c97d2d2a313e4f95957818a7b3edc\"\nALGOLIA_APPLICATION_ID=AB12CD34EF",
			Expect: []config.ExpectedFinding{
				{Secret: "bf5c97d2d2a313e4f95957818a7b3edc", ComponentSets: []map[string]string{{"algolia-application-id": "AB12CD34EF"}}},
			},
		},
	},
})
