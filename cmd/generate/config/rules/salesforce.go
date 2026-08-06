package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func SalesforceInstanceURL() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "salesforce-instance-url.1",
		Description: "Salesforce instance host, used as a component of the Salesforce access-token rule.",
		Regex: regexp.MustCompile(
			`(?i)(?:^|[^a-z0-9.-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,4}\.my\.salesforce\.com|[a-z]{2,8}[0-9]{1,4}\.salesforce\.com))(?:[^a-z0-9.-]|$)`,
		),
		Keywords:   []string{"salesforce.com"},
		SkipReport: true,
	}

	// validate
	tps := []string{
		`SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com`,
		`SALESFORCE_INSTANCE_URL=https://acme--dev.sandbox.my.salesforce.com`,
		`SALESFORCE_INSTANCE_URL=https://na123.salesforce.com`,
	}
	fps := []string{
		`SALESFORCE_INSTANCE_URL=https://example.com`,
		`SALESFORCE_INSTANCE_URL=https://-invalid.my.salesforce.com`,
		`SALESFORCE_INSTANCE_URL=https://my.salesforce.com.evil.example`,
	}
	return utils.Validate(r, tps, fps)
}

func SalesforceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "salesforce-access-token.1",
		Description: "Salesforce access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`00[A-Za-z0-9]{13}![A-Za-z0-9._-]{80,260}`, false),
		Keywords:    []string{"salesforce.com"},
		RequiredRules: []*config.Required{
			{RuleID: "salesforce-instance-url.1", WithinLines: utils.Ptr(30)},
		},
		ValidateExpr: `let r = http.get("https://" + captures["salesforce-instance-url.1"] + "/services/data/v67.0/limits", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"DailyApiRequests\"") ? {
    "result": "valid"
  } : r.status == 403 && (r.body contains "\"REQUEST_LIMIT_EXCEEDED\"") ? {
    "result": "valid",
    "reason": "Authenticated but the organization API request limit is exceeded"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	// validate
	tps := []string{
		"SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00" + secrets.NewSecret(`[A-Za-z0-9]{13}`) + "!" + secrets.NewSecretWithEntropy(`[A-Za-z0-9._-]{96}`, 3.3),
		`=== Org Description
Access Token      00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLEzmpkb58urFRkgeBGsxL_QJWwYMfAbUeeG7c1EXAMPLEDUkWe6H34r1AAwOR8B8fLEz6nEXAMPLEAAAA
Instance Url      https://MyDomainName.my.salesforce.com`,
	}
	fps := []string{
		"SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!short",
		"SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLEzmpkb58urFRkgeBGsxL/QJWwYMfAbUeeG7c1EXAMPLEDUkWe6H34r1AAwOR8B8fLEz6nEXAMPLEAAAA",
	}
	return utils.Validate(r, tps, fps)
}
