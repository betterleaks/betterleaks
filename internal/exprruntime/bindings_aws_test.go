package exprruntime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSValidation(t *testing.T) {
	for _, tc := range []struct {
		name               string
		status             int
		body, secret, want string
	}{
		{"valid", http.StatusOK, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult>
<Arn>arn:aws:iam::111111111111:user/dev</Arn>
<Account>111111111111</Account>
<UserId>AIDAEXAMPLE</UserId>
</GetCallerIdentityResult>
</GetCallerIdentityResponse>`, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "valid"},
		{"invalid", http.StatusForbidden, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`, "badkey", "invalid"},
		{"server error", http.StatusInternalServerError, "", "anykey", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.NotEmpty(t, r.Header.Get("Authorization"))
				assert.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			env, err := New(server.Client())
			require.NoError(t, err)
			env.STSEndpoint = server.URL
			program, err := env.CompileValidation(`
let response = aws.validate(finding.secret, components["aws-secret-access-key"]?.secret ?? "");
{"response": response, "result": response.status == 200 ? "valid" : response.status == 403 ? "invalid" : validate.unknown(response).result}`)
			require.NoError(t, err)
			got, err := env.EvalWithComponents(program,
				map[string]string{"secret": "AKIAIOSFODNN7EXAMPLE"}, nil,
				map[string]any{"aws-secret-access-key": map[string]any{"secret": tc.secret}})
			require.NoError(t, err)
			result := got.(map[string]any)
			assert.Equal(t, tc.want, result["result"])
			response := result["response"].(map[string]any)
			assert.Equal(t, int64(tc.status), response["status"])
			if tc.status == http.StatusOK {
				assert.Equal(t, "arn:aws:iam::111111111111:user/dev", response["arn"])
				assert.Equal(t, "111111111111", response["account"])
				assert.Equal(t, "AIDAEXAMPLE", response["userid"])
			} else {
				assert.NotContains(t, response, "arn")
			}
		})
	}
}
