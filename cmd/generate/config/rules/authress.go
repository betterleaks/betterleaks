package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func Authress() *config.Rule {
	// Rule Definition
	// (Note: When changes are made to this, rerun `go generate ./...` and commit the config/gitleaks.toml file
	r := config.Rule{
		RuleID:      "authress-service-client-access-key",
		Description: "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.",
		Regex:       regexp.MustCompile(`(?i)\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})\b`),
		Keywords:    []string{"sc_", "ext_", "scauth_", "authress_"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.authress.io/v1/users/me", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && !r.body.contains("\"Unauthorized\"") ? {
    "result": "valid"
  } : r.status in [401, 403] || r.body.contains("\"Unauthorized\"") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 4.0`,
	}

	// validate
	// https://authress.io/knowledge-base/docs/authorization/service-clients/secrets-scanning/#1-detection
	tps := []string{
		`authress_access_key = "sc_a6DTktFwMEvh87xstYV1BXl.ihwj.acc-0xd1a47h1rr0f.MC4CAQAwBQYDKAVwBCIEIB1wYB62EK24FKxEPHbW0ishcstwp2qs30uLXdWgu4V0"`,
	}
	fps := []string{
		`authress_access_key = "sc_bad.ihwj.acc-0xd1a47h1rr0f.MC4CAQAwBQYDKAVwBCIEIB1wYB62EK24FKxEPHbW0ishcstwp2qs30uLXdWgu4V0"`,
	}
	return utils.Validate(r, tps, fps)
}
