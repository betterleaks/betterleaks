package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

// TODO this one could probably use some work
func GCPServiceAccount() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\"type\": \"service_account\"`),
		Keywords:    []string{`\"type\": \"service_account\"`},
	}

	// validate
	tps := []string{
		`"type": "service_account"`,
	}
	return utils.Validate(r, tps, nil)
}

func GCPAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gcp-api-key",
		Description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIza[\w-]{35}`, false),
		Keywords:    []string{"AIza"},
		Filter: `entropy(finding["secret"]) <= 4.0
|| matchesAny(finding["secret"], [
  r"""AIzaSyabcdefghijklmnopqrstuvwxyz1234567""",
  r"""AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs""",
  r"""AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM""",
  r"""AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU""",
  r"""AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0""",
  r"""AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A""",
  r"""AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c""",
  r"""AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4""",
  r"""AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY""",
  r"""AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM""",
  r"""AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ""",
  r"""AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g""",
  r"""AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU""",
  r"""AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw""",
  r"""AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE""",
  r"""AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"""
])`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("gcp", secrets.NewSecretWithEntropy(`AIza[\w-]{35}`, 4))
	tps = append(tps,
		// non-word character at end
		`AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-`, // gitleaks:allow
	)
	fps := []string{
		`GWw4hjABFzZCGiRpmlDyDdo87Jn9BN9THUA47muVRNunLxsa82tMAdvmrhOqNkRKiYMEAFbTJAIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDq`, // text boundary start
		`AIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDqabcd123`,                                                                   // text boundary end
		`apiKey: "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,                                                                // not enough entropy
		`AIZASYCO2CXRMC9ELSKLHLHRMBSWDEVEDZTLO2O`,                                                                          // incorrect case
		// example keys from https://github.com/firebase/firebase-android-sdk
		`AIzaSyabcdefghijklmnopqrstuvwxyz1234567`,
		`AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`,
		`AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`,
		`AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`,
		`AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`,
		`AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`,
		`AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`,
		`AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`,
		`AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`,
		`AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`,
		`AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`,
		`AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`,
		`AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`,
		`AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`,
		`AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`,
		`AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`,
	}
	return utils.Validate(r, tps, fps)
}
