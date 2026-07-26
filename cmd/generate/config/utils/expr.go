package utils

import "fmt"

func MinEntropy(threshold float64) string {
	return fmt.Sprintf(`entropy(finding["secret"]) < %.1f`, threshold)
}

func BearerGetValidationExpr(url string, successCheck string) string {
	return `let r = http.get("` + url + `", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  });
r.status == 200 && (` + successCheck + `) ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
`
}

// BearerDeleteRevokeExpr builds a revoke expression for providers whose
// credential revocation is a DELETE request authenticated by the secret
// itself as a bearer token, succeeding on successStatus.
func BearerDeleteRevokeExpr(url string, successStatus int) string {
	return `let r = http.delete("` + url + `", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  });
r.status == ` + fmt.Sprintf("%d", successStatus) + ` ? {
    "result": "revoked"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "token was already invalid or unauthorized"
  } : revoke.unknown(r)
`
}
