package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Authress() *config.Rule {
	// Rule Definition
	// (Note: When changes are made to this, rerun `go generate ./...` and commit the config/gitleaks.toml file
	r := config.Rule{
		RuleID:      "authress-service-client-access-key",
		Description: "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.",
		Regex:       utils2.GenerateUniqueTokenRegex(`(?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}`, false),
		Entropy:     2,
		Keywords:    []string{"sc_", "ext_", "scauth_", "authress_"},
	}

	// validate
	// https://authress.io/knowledge-base/docs/authorization/service-clients/secrets-scanning/#1-detection
	service_client_id := "sc_" + utils2.AlphaNumeric("10")
	access_key_id := utils2.AlphaNumeric("4")
	account_id := "acc_" + utils2.AlphaNumeric("10")
	signature_key := utils2.AlphaNumericExtendedShort("40")

	tps := utils2.GenerateSampleSecrets("authress", secrets.NewSecret(fmt.Sprintf(`%s\.%s\.%s\.%s`, service_client_id, access_key_id, account_id, signature_key)))
	return utils2.Validate(r, tps, nil)
}
