package celenv

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/betterleaks/betterleaks/internal/sigv4"
)

// STS = Security Token Service
// https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
const (
	defaultSTSEndpoint = "https://sts.amazonaws.com/"
	stsRequestBody     = "Action=GetCallerIdentity&Version=2011-06-15"
)

// getCallerIdentityResult is the XML response from STS GetCallerIdentity.
// This is the 200 resp xml
type getCallerIdentityResult struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		Account string `xml:"Account"`
		UserID  string `xml:"UserId"`
	} `xml:"GetCallerIdentityResult"`
}

// stsErrorResponse is the XML error envelope returned by STS on non-200 responses.
type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Code    string   `xml:"Error>Code"`
	Message string   `xml:"Error>Message"`
}

// awsValidateBinding returns a CEL FunctionOp that calls STS GetCallerIdentity
// with SigV4-signed credentials and returns a result map similar to the
// http binding (map[string]any).
func awsValidateBinding(e *ValidationEnvironment) functions.FunctionOp {
	return func(args ...ref.Val) ref.Val {
		if len(args) != 2 {
			return types.NewErr("aws.validate: expected 2 args, got %d", len(args))
		}

		accessKeyID, ok := args[0].(types.String)
		if !ok {
			return types.NewErr("aws.validate: access_key_id must be a string")
		}
		secretAccessKey, ok := args[1].(types.String)
		if !ok {
			return types.NewErr("aws.validate: secret_access_key must be a string")
		}

		// TODO - This is hardcoded right now but in the future we could
		// introduce "optional" rule components like an STS endpoint.
		endpoint := e.STSEndpoint
		if endpoint == "" {
			endpoint = defaultSTSEndpoint
		}

		result := callSTS(e, endpoint, string(accessKeyID), string(secretAccessKey))
		return types.DefaultTypeAdapter.NativeToValue(result)
	}
}

// callSTS performs a SigV4-signed POST to the STS endpoint and returns a
// response map with {status, arn, account, userid}. The CEL expression is
// responsible for interpreting the status code and building the final result.
func callSTS(e *ValidationEnvironment, endpoint, accessKeyID, secretAccessKey string) map[string]any {
	body := stsRequestBody

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return map[string]any{"status": int64(0)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, []byte(body), "us-east-1", "sts", sigv4.Credentials{
		AccessKey: accessKeyID,
		SecretKey: secretAccessKey,
	}); err != nil {
		return map[string]any{"status": int64(0)}
	}

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
		e.captureDebug("POST", endpoint, body, req, resp, respBody)
	}

	result := map[string]any{
		"status": int64(resp.StatusCode),
	}

	// Parse XML identity fields when available.
	if resp.StatusCode == 200 {
		var identity getCallerIdentityResult
		if err := xml.Unmarshal(respBody, &identity); err == nil {
			result["arn"] = identity.Result.Arn
			result["account"] = identity.Result.Account
			result["userid"] = identity.Result.UserID
		}
	} else {
		var awsErr stsErrorResponse
		if err := xml.Unmarshal(respBody, &awsErr); err == nil {
			result["error_code"] = awsErr.Code
			result["error_message"] = awsErr.Message
		} else {
			// If it's not valid XML, it might be an HTML error from a WAF or Proxy
			result["error_message"] = "Non-XML error response received"
			result["error_code"] = ""
		}
	}
	return result
}
