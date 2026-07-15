package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AivenAuthToken() *config.Rule {
	r := config.Rule{
		RuleID:      "aiven-auth-token",
		Description: "Detected an Aiven authentication token, which may expose Aiven projects and services.",
		Regex:       regexp.MustCompile(`(?i:aiven)[\s\S]{0,32}?\b([A-Za-z0-9/+=]{372})(?:[^A-Za-z0-9/+=]|$)`),
		Keywords:    []string{"aiven"},
		ValidateExpr: `let r = http.get("https://api.aiven.io/v1/project", {
    "Authorization": "aivenv1 " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	token := "MOLXG502hGM9DsUSyvKVf2cx8zXEdBesHZLSqXnMj4agm9jLx4gpC9R+z26CX4tKgrIpjvR9dgorE/DzVxxH79Pd+mspIHgxkf7fL4eLxuFvl4RrvX9CWS7nMnfB9uDiM80AtGykzHm8KKr76I7UY8Az/i3x2OG5gFhH0+2AT0Qr75T1JbNF0IiPSjI3MQ0A1+k1b2DW2dwdNnYKEewrNjhVHre8sYLzMUE5Y+FIs8OFdpAm4YNUb283iVJjEcxT8AtMhmOrziMkmWn0haxjhT2qdxgnafGJidF0Dl/NIN+4o1WokQSyhHH1glhNV5wZcG4Po/KP3aPSRnrFE0+GZ6322TrWo1btS5mv+FKkS6gKq0zEfA=="
	return utils.Validate(r,
		[]string{`AIVEN_API_TOKEN="` + token + `"`, `Authorization: aivenv1 ` + token},
		[]string{`AIVEN_API_TOKEN="short"`, `token="` + token + `"`},
	)
}
