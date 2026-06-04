package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GCPApplicationDefaultCredentials() *config.Rule {
	r := config.Rule{
		Description: "Google (GCP) Application Default Credentials",
		RuleID:      "gcp-application-default-credentials",
		Regex:       regexp.MustCompile(`\{[^{]+(?:(?:"client_secret"\s*:\s*"[^"]+"[^}]+"refresh_token"\s*:\s*"[^"]+")|(?:"refresh_token"\s*:\s*"[^"]+"[^}]+"client_secret"\s*:\s*"[^"]+"))[^}]+\}`),
		Keywords:    []string{".apps.googleusercontent.com"},
		ValidateCEL: `cel.bind(r,
  gcp.validate(finding["secret"]),
  r.status == 200 ? {
    "result": "valid",
    "credential_type": r.credential_type,
    "client_id": r.client_id
  } : r.status in [400, 401] ? {
    "result": "invalid",
    "error_code": r.error_code,
    "error_message": r.error_message
  } : unknown(r)
)
`,
	}

	tps := []string{
		`{"client_id":"1234567890.apps.googleusercontent.com","client_secret":"GOCSPX-example","refresh_token":"1//refresh-token","type":"authorized_user"}`,
	}
	return utils.Validate(r, tps, nil)
}

func GCPServiceAccount() *config.Rule {
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\{[^{]+(?:(?:"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^}]+auth_provider_x509_cert_url)|(?:auth_provider_x509_cert_url[^}]+"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----))[^}]+\}`),
		Keywords:    []string{"provider_x509"},
		ValidateCEL: `cel.bind(r,
  gcp.validate(finding["secret"]),
  r.status == 200 ? {
    "result": "valid",
    "credential_type": r.credential_type,
    "project_id": r.project_id,
    "client_email": r.client_email
  } : r.status in [400, 401] ? {
    "result": "invalid",
    "error_code": r.error_code,
    "error_message": r.error_message
  } : unknown(r)
)
`,
		Filter: `containsAny(finding["secret"], ["image-pulling@authenticated-image-pulling.iam.gserviceaccount.com"])`,
	}

	tps := []string{
		`{"type":"service_account","project_id":"project-123","private_key_id":"key-id","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","client_email":"svc@project-123.iam.gserviceaccount.com","client_id":"1234567890","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/svc%40project-123.iam.gserviceaccount.com"}`,
		`{"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","token_uri":"https://oauth2.googleapis.com/token","client_email":"svc@project-123.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","project_id":"project-123","type":"service_account"}`,
	}
	fps := []string{
		`{"description":"Google service account key","type":"object","required":["type","project_id","private_key_id","private_key","client_email","client_id","auth_uri","token_uri","auth_provider_x509_cert_url","client_x509_cert_url"],"properties":{"type":{"const":"service_account"},"project_id":{"type":"string"},"private_key_id":{"type":"string"},"private_key":{"type":"string"},"client_email":{"type":"string"},"client_id":{"type":"string"},"auth_uri":{"type":"string"},"token_uri":{"type":"string"},"auth_provider_x509_cert_url":{"type":"string"},"client_x509_cert_url":{"type":"string"}}}`,
	}
	return utils.Validate(r, tps, fps)
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
