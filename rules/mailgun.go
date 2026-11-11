package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mailgun-private-api-token",
	Confidence:  "high",
	Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
	Regex:       Assignment([]string{"mailgun"}, `(?i)key-[a-f0-9]{32}`),

	Keywords: []string{
		"mailgun",
	},
	ValidateExpr: `let r = http.get("https://api.mailgun.net/v3/domains", {
    "Accept": "application/json",
    "Authorization": "Basic " + base64.encode(bytes("api:" + finding["secret"]))
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("mailgun assignment", `mailgunToken = "key-1f7b169c846f218ab552fa82fbf86758"`, "key-1f7b169c846f218ab552fa82fbf86758"),
	},
})

var _ = Add(config.Rule{
	ID:          "mailgun-pub-key",
	Confidence:  "high",
	Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
	Regex:       Assignment([]string{"mailgun"}, `(?i)pubkey-[a-f0-9]{32}`),

	Keywords: []string{
		"mailgun",
	},
	Tests: []config.RuleTest{
		Match("mailgun assignment", `mailgunToken = "pubkey-1f7b169c846f218ab552fa82fbf86758"`, "pubkey-1f7b169c846f218ab552fa82fbf86758"),
	},
})

var _ = Add(config.Rule{
	ID:          "mailgun-signing-key",
	Confidence:  "high",
	Description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
	Regex:       Assignment([]string{"mailgun"}, `(?i)[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}`),

	Keywords: []string{
		"mailgun",
	},
	Tests: []config.RuleTest{
		Match("mailgun assignment", `mailgunToken = "1f7b169c846f218ab552fa82fbf86758-00001111-22223333"`, "1f7b169c846f218ab552fa82fbf86758-00001111-22223333"),
	},
})
