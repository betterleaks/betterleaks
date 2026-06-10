package utils

import "fmt"

func MinEntropy(threshold float64) string {
	return fmt.Sprintf(`entropy(finding["secret"]) < %.1f`, threshold)
}

func BearerGetValidationCEL(url string, successCheck string) string {
	return `cel.bind(r,
  http.get("` + url + `", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && (` + successCheck + `) ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`
}
