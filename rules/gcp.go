package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const gcpAPIKeyValidationExpr = `let k = http.get("https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=" + finding["secret"], {}); k.status == 400 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : (let r = http.get("https://generativelanguage.googleapis.com/v1beta/models?key=" + finding["secret"], {}); r.status == 200 && (r.body contains '"models"') ? {
    "result": "valid",
    "metadata": {"active_google_key": true, "gemini_access": true}
  } : r.status == 403 && (r.body contains "API_KEY_HTTP_REFERRER_BLOCKED") ? {
    "result": "needs_validation",
    "reason": "Active Google API key blocked by HTTP referrer restriction",
    "metadata": {"active_google_key": true, "gemini_access": "unknown", "restriction": "http_referrer"}
  } : r.status == 403 && (r.body contains "API_KEY_IP_ADDRESS_BLOCKED") ? {
    "result": "needs_validation",
    "reason": "Active Google API key blocked by IP address restriction",
    "metadata": {"active_google_key": true, "gemini_access": "unknown", "restriction": "ip_address"}
  } : r.status == 403 && (r.body contains "API_KEY_IOS_APP_BLOCKED") ? {
    "result": "needs_validation",
    "reason": "Active Google API key blocked by iOS app restriction",
    "metadata": {"active_google_key": true, "gemini_access": "unknown", "restriction": "ios_app"}
  } : r.status == 403 && (r.body contains "API_KEY_ANDROID_APP_BLOCKED") ? {
    "result": "needs_validation",
    "reason": "Active Google API key blocked by Android app restriction",
    "metadata": {"active_google_key": true, "gemini_access": "unknown", "restriction": "android_app"}
  } : r.status == 403 && (r.body contains "API_KEY_SERVICE_BLOCKED") ? {
    "result": "needs_validation",
    "reason": "Active Google API key blocked from Gemini API",
    "metadata": {"active_google_key": true, "gemini_access": false}
  } : r.status == 403 ? {
    "result": "needs_validation",
    "reason": "Active Google API key with unknown Gemini access",
    "metadata": {"active_google_key": true, "gemini_access": "unknown"}
  } : r.status == 400 && k.status in [200, 403] ? {
    "result": "needs_validation",
    "reason": "Active Google API key not accepted by Gemini API",
    "metadata": {"active_google_key": true, "gemini_access": false}
  } : r.status == 400 && (r.body contains "API_KEY_INVALID") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : r.status == 400 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r))`

var _ = rulebuilder.Add(config.Rule{
	Description: "Google (GCP) Application Default Credentials",
	ID:          "gcp-application-default-credentials",
	Confidence:  "high",
	Regex:       `\{[^{]+(?:(?:"client_secret"\s*:\s*"[^"]+"[^}]+"refresh_token"\s*:\s*"[^"]+")|(?:"refresh_token"\s*:\s*"[^"]+"[^}]+"client_secret"\s*:\s*"[^"]+"))[^}]+\}`,
	Keywords:    []string{".apps.googleusercontent.com"},
	ValidateExpr: `let r = gcp.validate(finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "metadata": {"credential_type": r.credential_type, "client_id": r.client_id}
} : r.status in [400, 401] ? {
    "result": "invalid",
    "metadata": {"error_code": r.error_code, "error_message": r.error_message}
  } : validate.unknown(r)
`,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", `{"client_id":"1234567890.apps.googleusercontent.com","client_secret":"GOCSPX-example","refresh_token":"1//refresh-token","type":"authorized_user"}`, `{"client_id":"1234567890.apps.googleusercontent.com","client_secret":"GOCSPX-example","refresh_token":"1//refresh-token","type":"authorized_user"}`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Google (GCP) Service-account",
	ID:          "gcp-service-account",
	Confidence:  "high",
	Regex:       `\{[^{]+(?:(?:"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^}]+auth_provider_x509_cert_url)|(?:auth_provider_x509_cert_url[^}]+"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----))[^}]+\}`,
	Keywords:    []string{"provider_x509"},
	ValidateExpr: `let r = gcp.validate(finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "metadata": {"credential_type": r.credential_type, "project_id": r.project_id, "client_email": r.client_email}
} : r.status in [400, 401] ? {
    "result": "invalid",
    "metadata": {"error_code": r.error_code, "error_message": r.error_message}
  } : validate.unknown(r)
`,
	FilterExpr: `containsAny(finding["secret"], ["image-pulling@authenticated-image-pulling.iam.gserviceaccount.com"])`,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", `{"type":"service_account","project_id":"project-123","private_key_id":"key-id","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","client_email":"svc@project-123.iam.gserviceaccount.com","client_id":"1234567890","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/svc%40project-123.iam.gserviceaccount.com"}`, `{"type":"service_account","project_id":"project-123","private_key_id":"key-id","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","client_email":"svc@project-123.iam.gserviceaccount.com","client_id":"1234567890","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/svc%40project-123.iam.gserviceaccount.com"}`),
		rulebuilder.Match("bare secret 2", `{"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","token_uri":"https://oauth2.googleapis.com/token","client_email":"svc@project-123.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","project_id":"project-123","type":"service_account"}`, `{"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","token_uri":"https://oauth2.googleapis.com/token","client_email":"svc@project-123.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n","project_id":"project-123","type":"service_account"}`),
		rulebuilder.NoMatch("false positive 1", `{"description":"Google service account key","type":"object","required":["type","project_id","private_key_id","private_key","client_email","client_id","auth_uri","token_uri","auth_provider_x509_cert_url","client_x509_cert_url"],"properties":{"type":{"const":"service_account"},"project_id":{"type":"string"},"private_key_id":{"type":"string"},"private_key":{"type":"string"},"client_email":{"type":"string"},"client_id":{"type":"string"},"auth_uri":{"type":"string"},"token_uri":{"type":"string"},"auth_provider_x509_cert_url":{"type":"string"},"client_x509_cert_url":{"type":"string"}}}`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:           "gcp-api-key",
	Confidence:   "high",
	Description:  "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
	Regex:        rulebuilder.Token(`AIza[\w-]{35}`),
	Keywords:     []string{"aiza"},
	ValidateExpr: gcpAPIKeyValidationExpr,
	FilterExpr:   "entropy(finding[\"secret\"]) <= 4.0\n|| matchesAny(finding[\"secret\"], [\n  `AIzaSyabcdefghijklmnopqrstuvwxyz1234567`,\n  `AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs`,\n  `AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM`,\n  `AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU`,\n  `AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0`,\n  `AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A`,\n  `AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c`,\n  `AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4`,\n  `AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY`,\n  `AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM`,\n  `AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ`,\n  `AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g`,\n  `AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU`,\n  `AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw`,\n  `AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE`,\n  `AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY`\n])",
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `gcpToken = "AIzaWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_"`, "AIzaWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_"),
		rulebuilder.Match("bare secret", "AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-", "AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-"),
		rulebuilder.NoMatch("text boundary start", "GWw4hjABFzZCGiRpmlDyDdo87Jn9BN9THUA47muVRNunLxsa82tMAdvmrhOqNkRKiYMEAFbTJAIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDq"),
		rulebuilder.NoMatch("text boundary end", "AIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDqabcd123"),
		rulebuilder.NoMatch("not enough entropy", `apiKey: "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
		rulebuilder.NoMatch("incorrect case", "AIZASYCO2CXRMC9ELSKLHLHRMBSWDEVEDZTLO2O"),
		rulebuilder.NoMatch("example keys from https://github.com/firebase/firebase-android-sdk", "AIzaSyabcdefghijklmnopqrstuvwxyz1234567"),
		rulebuilder.NoMatch("false positive 1", "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs"),
		rulebuilder.NoMatch("false positive 2", "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM"),
		rulebuilder.NoMatch("false positive 3", "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU"),
		rulebuilder.NoMatch("false positive 4", "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0"),
		rulebuilder.NoMatch("false positive 5", "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A"),
		rulebuilder.NoMatch("false positive 6", "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c"),
		rulebuilder.NoMatch("false positive 7", "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4"),
		rulebuilder.NoMatch("false positive 8", "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY"),
		rulebuilder.NoMatch("false positive 9", "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM"),
		rulebuilder.NoMatch("false positive 10", "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ"),
		rulebuilder.NoMatch("false positive 11", "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g"),
		rulebuilder.NoMatch("false positive 12", "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU"),
		rulebuilder.NoMatch("false positive 13", "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw"),
		rulebuilder.NoMatch("false positive 14", "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE"),
		rulebuilder.NoMatch("false positive 15", "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:           "gcp-gemini-api",
	Confidence:   "high",
	Description:  "Detected a Google Gemini API key, which may expose Gemini model access and usage to unauthorized parties.",
	Regex:        rulebuilder.Token(`AQ\.Ab8RN6[A-Za-z0-9_-]{44}`),
	Keywords:     []string{"aq.ab8rn6"},
	ValidateExpr: gcpAPIKeyValidationExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `geminiToken = "AQ.Ab8RN6WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92"`, "AQ.Ab8RN6WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92"),
		rulebuilder.NoMatch("Wrong prefix", `gemini_api_key = "AQ.Ab8RN5AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AB"`),
		rulebuilder.NoMatch("Too short", `gemini_api_key = "AQ.Ab8RN6AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-"`),
	},
})
