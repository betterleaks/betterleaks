package validate_test

import (
	"context"
	"fmt"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/validate"
)

func ExampleValidator_ValidateCredential() {
	// Mock provider programs keep this example independent of network services.
	cfg := &config.Config{Rules: []config.Rule{{
		ID:           "demo-token",
		Regex:        `demo_(?P<tenant>[a-z]+)_(?P<key>[a-z]+)`,
		SecretGroup:  2,
		ValidateExpr: `finding.captures.tenant == "acme" ? {"result": "valid", "analysis": {"owner": "demo-user"}} : {"result": "invalid"}`,
		AnalyzeExpr:  `{"identity": {"username": validation["analysis"]["owner"]}, "capabilities": ["read"]}`,
	}}}
	validator, err := validate.NewValidator(cfg, validate.Options{
		Analysis: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	result, err := validator.ValidateCredential(context.Background(), validate.Credential{
		RuleID: "demo-token",
		Secret: "example",
		// Supply the named inputs the detection regex would otherwise extract.
		Captures: map[string]string{"tenant": "acme"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Validation.Status)
	fmt.Println(result.Analysis.Identity.Username)
	fmt.Println(result.Analysis.Severity)
	// Output:
	// valid
	// demo-user
	// medium
}
