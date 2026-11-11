package rules

import "github.com/betterleaks/betterleaks/v2/config"

// CratesIOAPIKey detects crates.io API tokens, which can publish, yank, and change owners of the user's crates.
//
// https://github.com/rust-lang/crates.io/blob/0ea9b2cc5237d037b7e690d26015bc458cf14d28/src/controllers/krate/search.rs#L420-L421
// https://github.com/rust-lang/crates.io/blob/0ea9b2cc5237d037b7e690d26015bc458cf14d28/src/auth.rs#L170-L177
// https://github.com/rust-lang/crates.io/blob/0ea9b2cc5237d037b7e690d26015bc458cf14d28/src/auth.rs#L311-L316
var _ = Add(config.Rule{
	ID:          "crates-io-api-key",
	Confidence:  "high",
	Description: "crates.io API key.",
	Regex:       Assignment([]string{`crates(?:[_.-]?io)?`}, `(?i)cio[A-Za-z0-9]{32}`),
	Keywords:    []string{"crates"},
	// crates.io rejects Go's default User-Agent with an empty 403. Scoped tokens lacking an endpoint scope get 403.
	ValidateExpr: `let r = http.get("https://crates.io/api/v1/crates?following=1&per_page=1", {
    "Authorization": finding["secret"],
    "Accept": "application/json",
    "User-Agent": "betterleaks-secret-validation/1"
  }); r.status == 200 ? {
    "result": "valid",
    "metadata": {"token_type": "legacy"}
  } : r.status == 403 && (r.body contains "this token does not have the required permissions to perform this action") ? {
    "result": "valid",
    "reason": "Scoped token lacks the crates endpoint scope",
    "metadata": {"token_type": "scoped"}
  } : r.status == 403 && (r.body contains "authentication failed") ? {
    "result": "invalid",
    "reason": "Unknown, revoked, or expired token"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("true positive 1", "CRATES_IO_API_KEY=ciotgp8BGZBlX192iExSQPm0SrUlBunG8zd", "ciotgp8BGZBlX192iExSQPm0SrUlBunG8zd"),
		NoMatch("false positive 1", "cio_short"),
	},
})
