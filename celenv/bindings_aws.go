package celenv

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
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

		now := time.Now().UTC()
		result := callSTS(e, endpoint, string(accessKeyID), string(secretAccessKey), now)
		return types.DefaultTypeAdapter.NativeToValue(result)
	}
}

// callSTS performs a SigV4-signed POST to the STS endpoint and returns a
// response map with {status, arn, account, userid}. The CEL expression is
// responsible for interpreting the status code and building the final result.
func callSTS(e *ValidationEnvironment, endpoint, accessKeyID, secretAccessKey string, now time.Time) map[string]any {
	body := stsRequestBody
	bodyHash := sha256Hex([]byte(body))

	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	region := "us-east-1"
	service := "sts"

	// Determine host from endpoint.
	host := "sts.amazonaws.com"
	if strings.Contains(endpoint, "://") {
		parts := strings.SplitN(endpoint, "://", 2)
		host = strings.TrimRight(parts[1], "/")
	}

	// Canonical request.
	canonicalHeaders := fmt.Sprintf("content-type:application/x-www-form-urlencoded\nhost:%s\nx-amz-date:%s\n", host, amzDate)
	signedHeaders := "content-type;host;x-amz-date"
	canonicalRequest := fmt.Sprintf("POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, bodyHash)

	// String to sign.
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)))

	// Signing key.
	signingKey := deriveSigningKey(secretAccessKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Authorization header.
	authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credentialScope, signedHeaders, signature)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return map[string]any{"status": int64(0)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authorization)

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

// deriveSigningKey derives the SigV4 signing key.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
