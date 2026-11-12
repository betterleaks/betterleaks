package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "planetscale-password",
	Confidence:  "high",
	Description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
	Regex:       rulebuilder.Token(`(?i)pscale_pw_(?i)[\w=\.-]{32,64}`),
	Keywords: []string{
		"pscale_pw_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `planetScaleToken = "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-"`, "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-"),
		rulebuilder.Match("planetScale assignment 2", `planetScaleToken = "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"`, "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"),
		rulebuilder.Match("planetScale assignment 3", `planetScaleToken = "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"`, "pscale_pw_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"),
	},
})

// PlanetScaleID detects PlanetScale service token IDs.
// This is a dependency rule for PlanetScaleAPIToken and is not reported on its own.
var _ = rulebuilder.Add(config.Rule{
	ID:          "planetscale-id",
	Confidence:  "high",
	Description: "Found a PlanetScale service token ID.",
	Regex:       `(?i)(?:pscale|planetscale)(?:.|[\n\r]){0,16}?(?:USER|ID|NAME)(?:.|[\n\r]){0,16}?([a-z0-9]{12})`,
	Keywords:    []string{"pscale", "planetscale"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "pscale_user = 0dm7fw8prpel", "0dm7fw8prpel"),
		rulebuilder.MatchComponent("true positive 2", "planetscale_id: 0dm7fw8prpel", "0dm7fw8prpel"),
		rulebuilder.MatchComponent("true positive 3", "PSCALE_USER_NAME = 5fbbd6p84oe7", "5fbbd6p84oe7"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "planetscale-api-token",
	Confidence:  "high",
	Description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
	Regex:       rulebuilder.Token(`pscale_tkn_(?i)[\w=\.-]{32,64}`),
	Keywords: []string{
		"pscale_tkn_",
	},
	Components: []config.Component{
		{RuleID: "planetscale-id"},
	},
	ValidateExpr: `let r = http.get("https://api.planetscale.com/v1/organizations", {
    "Accept": "application/json",
    "Authorization": (components["planetscale-id"]?.secret ?? "") + ":" + finding["secret"]
  }); r.status == 200 && (r.json?.type ?? "") == "list" ? {
    "result": "valid",
    "metadata": {"organization": r.json?.data?.[0]?.name ?? ""}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "assignment",
			Input: "planetScaleToken = \"pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-\"\npscale_user = 0dm7fw8prpel",
			Expect: []config.ExpectedFinding{
				{Secret: "pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-", ComponentSets: []map[string]string{{"planetscale-id": "0dm7fw8prpel"}}},
			},
		},
		{
			Name:  "planetScale assignment 2",
			Input: "planetScaleToken = \"pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903\"\npscale_user = 0dm7fw8prpel",
			Expect: []config.ExpectedFinding{
				{Secret: "pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903", ComponentSets: []map[string]string{{"planetscale-id": "0dm7fw8prpel"}}},
			},
		},
		{
			Name:  "planetScale assignment 3",
			Input: "planetScaleToken = \"pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r\"\npscale_user = 0dm7fw8prpel",
			Expect: []config.ExpectedFinding{
				{Secret: "pscale_tkn_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r", ComponentSets: []map[string]string{{"planetscale-id": "0dm7fw8prpel"}}},
			},
		},
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "planetscale-oauth-token",
	Confidence:  "high",
	Description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
	Regex:       rulebuilder.Token(`pscale_oauth_[\w=\.-]{32,64}`),
	Keywords: []string{
		"pscale_oauth_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `planetScaleToken = "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-"`, "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-"),
		rulebuilder.Match("planetScale assignment 2", `planetScaleToken = "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"`, "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"),
		rulebuilder.Match("planetScale assignment 3", `planetScaleToken = "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"`, "pscale_oauth_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"),
	},
})
