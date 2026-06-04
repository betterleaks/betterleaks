package celenv

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const (
	defaultGCPTokenEndpoint = "https://oauth2.googleapis.com/token"
	gcpOAuthScope           = "https://www.googleapis.com/auth/cloud-platform"
	gcpJWTBearerGrant       = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type gcpCredential struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	TokenURI     string `json:"token_uri"`
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func gcpBindings(e *ValidationEnvironment) []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("gcp.validate",
			cel.Overload("gcp_validate_string",
				[]*cel.Type{cel.StringType},
				cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(gcpValidateBinding(e)),
			),
		),
	}
}

func gcpValidateBinding(e *ValidationEnvironment) functions.UnaryOp {
	return func(arg ref.Val) ref.Val {
		credentialJSON, ok := arg.(types.String)
		if !ok {
			return types.NewErr("gcp.validate: credential_json must be a string")
		}

		result := validateGCPCredential(e, string(credentialJSON))
		return types.DefaultTypeAdapter.NativeToValue(result)
	}
}

func validateGCPCredential(e *ValidationEnvironment, credentialJSON string) map[string]any {
	creds, err := parseGCPCredential(credentialJSON)
	if err != nil {
		return map[string]any{
			"status":        int64(400),
			"error_code":    "invalid_credential_json",
			"error_message": err.Error(),
		}
	}

	tokenURL := strings.TrimSpace(creds.TokenURI)
	if tokenURL == "" {
		tokenURL = defaultGCPTokenEndpoint
	}
	if e.GCPTokenEndpoint != "" {
		tokenURL = e.GCPTokenEndpoint
	} else if !isAllowedGCPTokenEndpoint(tokenURL) {
		return map[string]any{
			"status":        int64(0),
			"error_code":    "unsupported_token_uri",
			"error_message": "GCP token URI is not an allowed Google OAuth endpoint",
		}
	}

	form, err := gcpTokenRequestForm(creds, tokenURL)
	if err != nil {
		return map[string]any{
			"status":          int64(400),
			"error_code":      "invalid_credential",
			"error_message":   err.Error(),
			"credential_type": creds.Type,
		}
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return map[string]any{"status": int64(0)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return map[string]any{"status": int64(0)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return map[string]any{"status": int64(resp.StatusCode)}
	}

	if e.DebugResponse {
		e.captureDebug("POST", tokenURL, form.Encode(), req, resp, respBody)
	}

	result := map[string]any{
		"status":          int64(resp.StatusCode),
		"credential_type": creds.Type,
	}
	if creds.ProjectID != "" {
		result["project_id"] = creds.ProjectID
	}
	if creds.ClientEmail != "" {
		result["client_email"] = creds.ClientEmail
	}
	if creds.ClientID != "" {
		result["client_id"] = creds.ClientID
	}

	var tokenResp gcpTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err == nil {
		if tokenResp.Error != "" {
			result["error_code"] = tokenResp.Error
		}
		if tokenResp.ErrorDesc != "" {
			result["error_message"] = tokenResp.ErrorDesc
		}
		if resp.StatusCode == http.StatusOK && tokenResp.AccessToken == "" {
			result["status"] = int64(0)
			result["error_code"] = "missing_access_token"
			result["error_message"] = "GCP token response did not include access_token"
		}
	}

	return result
}

func parseGCPCredential(input string) (gcpCredential, error) {
	input = cleanGCPCredentialInput(input)

	var creds gcpCredential
	if err := json.Unmarshal([]byte(input), &creds); err != nil {
		return gcpCredential{}, err
	}

	creds.ClientEmail = cleanGCPCredentialString(creds.ClientEmail)
	creds.TokenURI = cleanGCPCredentialString(creds.TokenURI)

	switch creds.Type {
	case "service_account":
		if creds.ProjectID == "" || creds.ClientEmail == "" || creds.PrivateKey == "" {
			return gcpCredential{}, errMissingGCPFields("project_id/client_email/private_key")
		}
	case "authorized_user":
		if creds.ClientID == "" || creds.ClientSecret == "" || creds.RefreshToken == "" {
			return gcpCredential{}, errMissingGCPFields("client_id/client_secret/refresh_token")
		}
	default:
		return gcpCredential{}, errMissingGCPFields("supported type")
	}

	return creds, nil
}

type errMissingGCPFields string

func (e errMissingGCPFields) Error() string {
	return "missing required GCP fields: " + string(e)
}

func gcpTokenRequestForm(creds gcpCredential, tokenURL string) (url.Values, error) {
	switch creds.Type {
	case "service_account":
		jwt, err := createGCPServiceAccountJWT(creds.ClientEmail, creds.PrivateKey, tokenURL)
		if err != nil {
			return nil, err
		}
		return url.Values{
			"grant_type": {gcpJWTBearerGrant},
			"assertion":  {jwt},
		}, nil
	case "authorized_user":
		return url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {creds.ClientID},
			"client_secret": {creds.ClientSecret},
			"refresh_token": {creds.RefreshToken},
		}, nil
	default:
		return nil, errMissingGCPFields("supported type")
	}
}

func createGCPServiceAccountJWT(clientEmail, privateKeyPEM, tokenURI string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":   clientEmail,
		"scope": gcpOAuthScope,
		"aud":   tokenURI,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	}
	headerJSON, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	privateKey, err := parseGCPPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseGCPPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errMissingGCPFields("PEM private_key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errMissingGCPFields("RSA private_key")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func cleanGCPCredentialInput(input string) string {
	input = strings.ReplaceAll(input, `,\\n`, `\n`)
	input = strings.ReplaceAll(input, `\"\\n`, `\n`)
	input = strings.ReplaceAll(input, `\\"`, `"`)
	if strings.Contains(input, `\"type\"`) {
		if unquoted, err := strconv.Unquote(`"` + input + `"`); err == nil {
			return unquoted
		}
	}
	return input
}

func cleanGCPCredentialString(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "<mailto:") {
		s = strings.Split(strings.Split(s, "<mailto:")[1], "|")[0]
	}
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

func isAllowedGCPTokenEndpoint(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimRight(u.EscapedPath(), "/")
	if host == "oauth2.googleapis.com" && path == "/token" {
		return true
	}
	if host == "accounts.google.com" && path == "/o/oauth2/token" {
		return true
	}
	return false
}
