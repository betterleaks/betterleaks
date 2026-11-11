package rules

import "fmt"

// Character classes shared by provider regexes. size is a regex quantifier
// body, such as "32" or "32,64".

func Numeric(size string) string {
	return fmt.Sprintf(`[0-9]{%s}`, size)
}

func Hex(size string) string {
	return fmt.Sprintf(`[a-f0-9]{%s}`, size)
}

func AlphaNumeric(size string) string {
	return fmt.Sprintf(`[a-z0-9]{%s}`, size)
}

func AlphaNumericExtendedShort(size string) string {
	return fmt.Sprintf(`[a-z0-9_-]{%s}`, size)
}

func AlphaNumericExtended(size string) string {
	return fmt.Sprintf(`[a-z0-9=_\-]{%s}`, size)
}

func AlphaNumericExtendedLong(size string) string {
	return fmt.Sprintf(`[a-z0-9\/=_\+\-]{%s}`, size)
}

func Hex8_4_4_4_12() string {
	return `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
}

func MinEntropy(threshold float64) string {
	return fmt.Sprintf(`entropy(finding["secret"]) < %.1f`, threshold)
}

const MinEntropyAndTokenEfficiency = `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`

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
