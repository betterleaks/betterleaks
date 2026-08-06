package exprruntime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testAzureKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestAzureValidateStorageExprBindingValid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "comp=list" {
			t.Errorf("unexpected query %q", got)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "SharedKey acct:") {
			t.Errorf("unexpected auth %q", got)
		}
		if got := r.Header.Get("x-ms-version"); got != azureStorageVersion {
			t.Errorf("unexpected x-ms-version %q", got)
		}
		fmt.Fprint(w, `<EnumerationResults><Containers><Container><Name>logs</Name></Container></Containers></EnumerationResults>`)
	}))
	defer ts.Close()

	env, err := New(ts.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.AzureStorageEndpoint = ts.URL + "/?comp=list"

	prg, err := env.CompileValidation(`let r = azure.validateStorage(captures["account"], finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "account": r.account,
  "containers": r.containers
} : validate.unknown(r)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := env.Eval(prg, map[string]string{"secret": testAzureKey}, map[string]string{"account": "acct"})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	result := got.(map[string]any)
	if result["result"] != "valid" {
		t.Fatalf("expected valid, got %v", result)
	}
	if result["account"] != "acct" {
		t.Errorf("unexpected account %v", result["account"])
	}
}

func TestAzureValidateServicePrincipalInvalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("unexpected grant_type %q", got)
		}
		if got := r.Form.Get("client_id"); got != "client-id" {
			t.Errorf("unexpected client_id %q", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"bad secret"}`)
	}))
	defer ts.Close()

	env, err := New(ts.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.AzureTokenEndpoint = ts.URL

	prg, err := env.CompileValidation(`let r = azure.validateServicePrincipal(captures["tenant"], captures["client"], finding["secret"]); r.status in [400, 401, 403] ? {
  "result": "invalid",
  "error_code": r.error_code
} : validate.unknown(r)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := env.Eval(prg, map[string]string{"secret": "client-secret"}, map[string]string{"tenant": "tenant.example", "client": "client-id"})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	result := got.(map[string]any)
	if result["result"] != "invalid" || result["error_code"] != "invalid_client" {
		t.Fatalf("unexpected result %v", result)
	}
}

func TestAzureValidateAppConfigValid(t *testing.T) {
	var serverHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.String(); got != "/custom-kv?api-version=test" {
			t.Errorf("unexpected URL %q", got)
		}
		if got := r.Host; got != serverHost {
			t.Errorf("unexpected host %q", got)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "HMAC-SHA256 Credential=id123") {
			t.Errorf("unexpected auth %q", got)
		}
		fmt.Fprint(w, `{"items":[]}`)
	}))
	defer ts.Close()
	serverHost = strings.TrimPrefix(ts.URL, "http://")

	env, err := New(ts.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.AzureAppConfigEndpoint = ts.URL + "/custom-kv?api-version=test"

	prg, err := env.CompileValidation(`let r = azure.validateAppConfig(captures["endpoint"], captures["id"], finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "id": r.id
} : validate.unknown(r)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := env.Eval(prg, map[string]string{"secret": testAzureKey}, map[string]string{"endpoint": "https://demo.azconfig.io", "id": "id123"})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	result := got.(map[string]any)
	if result["result"] != "valid" || result["id"] != "id123" {
		t.Fatalf("unexpected result %v", result)
	}
}

func TestAzureValidateServiceBusSASValid(t *testing.T) {
	var expectedResource string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "SharedAccessSignature ") {
			t.Errorf("unexpected auth %q", got)
		} else if strings.Contains(got, "api-version") {
			t.Errorf("SAS resource URI should not include query string: %q", got)
		} else if sr := serviceBusSASResource(t, got); sr != expectedResource {
			t.Errorf("unexpected SAS resource URI %q", sr)
		}
		if got := r.URL.Path; got != "/orders" {
			t.Errorf("unexpected path %q", got)
		}
		fmt.Fprint(w, `<entry></entry>`)
	}))
	defer ts.Close()
	expectedResource = ts.URL + "/orders"

	env, err := New(ts.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.AzureServiceBusEndpoint = ts.URL + "/orders?api-version=2017-04"
	conn := "Endpoint=sb://orders.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=" + testAzureKey + ";EntityPath=orders"

	prg, err := env.CompileValidation(`let r = azure.validateServiceBusSAS(finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "entity_path": r.entity_path
} : validate.unknown(r)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := env.Eval(prg, map[string]string{"secret": conn}, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	result := got.(map[string]any)
	if result["result"] != "valid" || result["entity_path"] != "orders" {
		t.Fatalf("unexpected result %v", result)
	}
}

func serviceBusSASResource(t *testing.T, auth string) string {
	t.Helper()
	values, err := url.ParseQuery(strings.TrimPrefix(auth, "SharedAccessSignature "))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	return values.Get("sr")
}

func TestParseAzureConnectionString(t *testing.T) {
	got := parseAzureConnectionString("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=name;SharedAccessKey=key;EntityPath=events")
	if got["endpoint"] != "sb://ns.servicebus.windows.net/" ||
		got["sharedaccesskeyname"] != "name" ||
		got["sharedaccesskey"] != "key" ||
		got["entitypath"] != "events" {
		t.Fatalf("unexpected parse: %v", got)
	}
}
