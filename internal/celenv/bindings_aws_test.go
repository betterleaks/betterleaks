package celenv

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCallSTS_Valid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("missing Authorization header")
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		w.WriteHeader(200)
		fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/testuser</Arn>
    <Account>123456789012</Account>
    <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`)
	}))
	defer ts.Close()

	e := &ValidationEnvironment{client: ts.Client()}
	result := callSTS(e, ts.URL, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

	if result["status"] != int64(200) {
		t.Fatalf("expected status 200, got %v", result["status"])
	}
	if result["arn"] != "arn:aws:iam::123456789012:user/testuser" {
		t.Errorf("unexpected arn: %v", result["arn"])
	}
	if result["account"] != "123456789012" {
		t.Errorf("unexpected account: %v", result["account"])
	}
	if result["userid"] != "AIDACKCEVSQ6C2EXAMPLE" {
		t.Errorf("unexpected userid: %v", result["userid"])
	}
}

func TestCallSTS_Invalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`)
	}))
	defer ts.Close()

	e := &ValidationEnvironment{client: ts.Client()}
	result := callSTS(e, ts.URL, "AKIAIOSFODNN7EXAMPLE", "badkey")

	if result["status"] != int64(403) {
		t.Fatalf("expected status 403, got %v", result["status"])
	}
	if _, ok := result["arn"]; ok {
		t.Error("expected no arn for 403 response")
	}
}

func TestCallSTS_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	e := &ValidationEnvironment{client: ts.Client()}
	result := callSTS(e, ts.URL, "AKIAIOSFODNN7EXAMPLE", "anykey")

	if result["status"] != int64(500) {
		t.Fatalf("expected status 500, got %v", result["status"])
	}
}

func TestAWSValidateCELBinding_Valid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::111111111111:user/dev</Arn>
    <Account>111111111111</Account>
    <UserId>AIDAEXAMPLE</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`)
	}))
	defer ts.Close()

	env, err := NewEnvironment(ts.Client())
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}
	env.STSEndpoint = ts.URL

	expr := `cel.bind(r,
  aws.validate(finding["secret"], captures["aws-secret-access-key"]),
  r.status == 200 ? {
    "result": "valid",
    "arn": r.arn,
    "account": r.account,
    "userid": r.userid
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`
	prg, err := env.Compile(expr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	finding := map[string]string{
		"secret": "AKIAIOSFODNN7EXAMPLE",
	}
	captures := map[string]string{
		"aws-secret-access-key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	got, err := env.Eval(prg, finding, captures)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	m, err := got.ConvertToNative(mapAnyType)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	result := m.(map[string]any)
	if result["result"] != "valid" {
		t.Errorf("expected valid, got %v", result["result"])
	}
	if result["account"] != "111111111111" {
		t.Errorf("expected account 111111111111, got %v", result["account"])
	}
}

func TestAWSValidateCELBinding_Invalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()

	env, err := NewEnvironment(ts.Client())
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}
	env.STSEndpoint = ts.URL

	expr := `cel.bind(r,
  aws.validate(finding["secret"], captures["aws-secret-access-key"]),
  r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`
	prg, err := env.Compile(expr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	finding := map[string]string{
		"secret": "AKIAIOSFODNN7EXAMPLE",
	}
	captures := map[string]string{
		"aws-secret-access-key": "badkey",
	}
	got, err := env.Eval(prg, finding, captures)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	m, err := got.ConvertToNative(mapAnyType)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	result := m.(map[string]any)
	if result["result"] != "invalid" {
		t.Errorf("expected invalid, got %v", result["result"])
	}
}
