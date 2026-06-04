package celenv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGCPValidateCELBinding_ServiceAccountValid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != gcpJWTBearerGrant {
			t.Errorf("unexpected grant_type %q", got)
		}
		if assertion := r.Form.Get("assertion"); strings.Count(assertion, ".") != 2 {
			t.Errorf("expected JWT assertion, got %q", assertion)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"ya29.test","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer ts.Close()

	env, err := NewEnvironment(ts.Client())
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}
	env.GCPTokenEndpoint = ts.URL

	prg, err := env.Compile(`cel.bind(r,
  gcp.validate(finding["secret"]),
  r.status == 200 ? {
    "result": "valid",
    "project_id": r.project_id,
    "client_email": r.client_email,
    "credential_type": r.credential_type
  } : r.status in [400, 401] ? {
    "result": "invalid",
    "reason": r.error_code
  } : unknown(r)
)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	got, err := env.Eval(prg, map[string]string{"secret": testGCPServiceAccountJSON(t, ts.URL)}, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	m, err := got.ConvertToNative(mapAnyType)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	result := m.(map[string]any)
	if result["result"] != "valid" {
		t.Fatalf("expected valid, got %v", result["result"])
	}
	if result["project_id"] != "test-project" {
		t.Errorf("unexpected project_id: %v", result["project_id"])
	}
	if result["client_email"] != "svc@test-project.iam.gserviceaccount.com" {
		t.Errorf("unexpected client_email: %v", result["client_email"])
	}
	if result["credential_type"] != "service_account" {
		t.Errorf("unexpected credential_type: %v", result["credential_type"])
	}
}

func TestGCPValidateCELBinding_ApplicationDefaultCredentialsInvalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("unexpected grant_type %q", got)
		}
		if got := r.Form.Get("client_id"); got != "client.apps.googleusercontent.com" {
			t.Errorf("unexpected client_id %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-token" {
			t.Errorf("unexpected refresh_token %q", got)
		}

		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`)
	}))
	defer ts.Close()

	env, err := NewEnvironment(ts.Client())
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}
	env.GCPTokenEndpoint = ts.URL

	prg, err := env.Compile(`cel.bind(r,
  gcp.validate(finding["secret"]),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [400, 401] ? {
    "result": "invalid",
    "error_code": r.error_code
  } : unknown(r)
)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	adc := `{"type":"authorized_user","client_id":"client.apps.googleusercontent.com","client_secret":"secret","refresh_token":"refresh-token"}`
	got, err := env.Eval(prg, map[string]string{"secret": adc}, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	m, err := got.ConvertToNative(mapAnyType)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	result := m.(map[string]any)
	if result["result"] != "invalid" {
		t.Fatalf("expected invalid, got %v", result["result"])
	}
	if result["error_code"] != "invalid_grant" {
		t.Errorf("unexpected error_code: %v", result["error_code"])
	}
}

func TestValidateGCPCredential_DisallowsNonGoogleTokenEndpoint(t *testing.T) {
	result := validateGCPCredential(&ValidationEnvironment{client: DefaultHTTPClient()}, testGCPServiceAccountJSON(t, "http://127.0.0.1/token"))

	if result["status"] != int64(0) {
		t.Fatalf("expected status 0, got %v", result["status"])
	}
	if result["error_code"] != "unsupported_token_uri" {
		t.Errorf("unexpected error_code: %v", result["error_code"])
	}
}

func testGCPServiceAccountJSON(t *testing.T, tokenURI string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}))

	b, err := json.Marshal(map[string]string{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "key-id",
		"private_key":                 keyPEM,
		"client_email":                "svc@test-project.iam.gserviceaccount.com",
		"client_id":                   "1234567890",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   tokenURI,
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/svc%40test-project.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("Marshal credential: %v", err)
	}
	return string(b)
}
