package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func BrowserStackUsername() *config.Rule {
	r := config.Rule{
		RuleID:      "browserstack-username.1",
		Confidence:  "medium",
		Description: "BrowserStack username, used as a component of the BrowserStack access-key composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`browserstack[_.-]?(?:username|user)`},
			`[A-Za-z0-9][A-Za-z0-9._-]{2,39}`,
			false,
		),
		Keywords:   []string{"browserstack"},
		SkipReport: true,
		Filter:     utils.MinEntropy(2.0),
	}

	username := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{12}`, 2.0)
	tps := []string{
		`BROWSERSTACK_USERNAME=` + username,
		`browserstack.user: "` + username + `"`,
	}
	fps := []string{
		`USERNAME=` + username,
		`BROWSERSTACK_USERNAME=ab`,
		`BROWSERSTACK_USERNAME=aaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}

func BrowserStackAccessKey() *config.Rule {
	r := config.Rule{
		RuleID:      "browserstack-access-key.1",
		Confidence:  "high",
		Description: "BrowserStack access key, which may allow access to automated browser and device testing when paired with its username.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`browserstack[_.-]?(?:access[_.-]?)?(?:key|secret|token)`},
			`[A-Za-z0-9]{20}`,
			false,
		),
		Keywords: []string{"browserstack"},
		Components: []*config.Component{
			{RuleID: "browserstack-username.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.get("https://api.browserstack.com/automate/plan.json", {
    "Authorization": "Basic " + base64.encode(bytes((components["browserstack-username.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json",
    "User-Agent": "betterleaks-secret-validation/1"
  }); r.status == 200 && (r.body contains "\"automate_plan\"") ? {
    "result": "valid"
  } : r.status == 403 && ((r.body contains "blocked") || (r.body contains "Blocked")) ?
    validate.unknown(r) : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	accessKey := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{20}`, 3.0)
	tps := []string{
		`BROWSERSTACK_ACCESS_KEY=` + accessKey,
		`browserstack.access_key: "` + accessKey + `"`,
	}
	fps := []string{
		`ACCESS_KEY=` + accessKey,
		`BROWSERSTACK_ACCESS_KEY=short`,
		`BROWSERSTACK_ACCESS_KEY=00000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
