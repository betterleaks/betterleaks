package rules

import "github.com/betterleaks/betterleaks/v2/config"

// OpenShift 4 user tokens are prefixed with `sha256~`.
// https://docs.redhat.com/en/documentation/openshift_container_platform/4.10/html-single/authentication_and_authorization/index#oauth-view-details-tokens_managing-oauth-access-tokens
var _ = Add(config.Rule{
	ID:          "openshift-user-token",
	Confidence:  "high",
	Description: "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
	// TODO: Do tokens vary in length or are they always 43?
	Regex: `\b(sha256~[\w-]{43})(?:[^\w-]|\z)`,
	Keywords: []string{
		"sha256~",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("oc assignment", `ocToken = "sha256~WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"`, "sha256~WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		Match("true positive 1", "Authorization: Bearer sha256~kV46hPnEYhCWFnB85r5NrprAxggzgb6GOeLbgcKNsH0", "sha256~kV46hPnEYhCWFnB85r5NrprAxggzgb6GOeLbgcKNsH0"),
		Match("true positive 2", "oc login --token=sha256~ZBMKw9VAayhdnyANaHvjJeXDiGwA7Fsr5gtLKj3-eh- ", "sha256~ZBMKw9VAayhdnyANaHvjJeXDiGwA7Fsr5gtLKj3-eh-"),
		Match("bare secret", "sha256~WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "sha256~WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		NoMatch("https://github.com/krkn-chaos/krkn/blob/f3933f0e6239824eb9b5c46ff0e5d503b8465d6a/docs/index.md?plain=1#L307", `--set kraken.kubeconfig.token.token="sha256~XXXXXXXXXX_PUT_YOUR_TOKEN_HERE_XXXXXXXXXXXX" \`),
		NoMatch("false positive 1", "oc login --token=sha256~_xxxxxx_xxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxx-X \\\n    --server=https://api.${zone}.appuio.cloud:6443"),
	},
})
