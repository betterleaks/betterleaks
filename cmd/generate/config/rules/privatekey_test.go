package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/regexp"
)

// TestPrivateKeyRuleShape pins the structural contract of the private-key
// regex: a real PEM must carry a base64 body and terminate with a full
// -----END ... PRIVATE KEY----- marker (see issue #374), while prose
// placeholders, redaction notes and truncated bodies must not fire.
// The RFC 1421 legacy-encrypted PEM branch keeps Proc-Type/DEK-Info keys
// detectable, which the plain base64 class alone would drop.
func TestPrivateKeyRuleShape(t *testing.T) {
	rule := PrivateKey()
	require.Equal(t, "private-key", rule.ID)

	// deterministic base64-looking bodies for the fixtures
	body64 := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8" +
		"Ks14IReLcYgADhoXk56ZzXI="

	tests := []struct {
		name  string
		value string
		match bool
	}{
		// true positives: every real PEM shape keeps firing
		{"pkcs8", "-----BEGIN PRIVATE KEY-----\n" + body64 + "\n-----END PRIVATE KEY-----", true},
		{"rsa", "-----BEGIN RSA PRIVATE KEY-----\n" + body64 + "\n-----END RSA PRIVATE KEY-----", true},
		{"pgp block", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic\n=8xQN\n-----END PGP PRIVATE KEY BLOCK-----", true},
		{"openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBAoQX\n5Q0DGCTC4R8H9QshPxrUPnOJs0rV2Xaw8sLAKn7MDQ==\n-----END OPENSSH PRIVATE KEY-----", true},
		{"ec", "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBrc1viCT7BVjbpcSzKq1PkuKsE2wZ2kot9O3UC4CJEEAakgBggqhkjOPQMB\nBaEDMgAEAKkCg1FD\n-----END EC PRIVATE KEY-----", true},
		{"crlf line endings", "-----BEGIN PRIVATE KEY-----\r\n" + body64 + "\r\n-----END PRIVATE KEY-----", true},
		{"single-line embedded in json", `{"key": "` + "-----BEGIN PRIVATE KEY-----" + body64 + "-----END PRIVATE KEY-----" + `"}`, true},
		// legacy RFC 1421 encrypted PEMs: Proc-Type/DEK-Info branch
		{"legacy des-ede3", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,8C2C29C4D3B9A1E7\n\n" + "7f3dKq9LmX2vPq8sTU2vBn3kMw9rXy5aQz8cVd1fHg4jKi7oPz6sRt2eWb5mNq1uY0xZr9tKd4fSg7hUz8aVb3nM==\n-----END RSA PRIVATE KEY-----\n", true},
		{"legacy aes-256", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,FB4A3B7CD8E91F05A6C2D4E7F8901234\n\n" + "MIIFLTBXBE9tKbCUBKtJkQNCxUUyFEEtBTvHoloMm1MszT5kA0OBk2ZfS5cV7LpEy\nXaQqGWQvNnpWzNslqyP4TQ==\n-----END ENCRYPTED PRIVATE KEY-----\n", true},

		// false positives from the issue and its comment thread
		{"placeholder prose", "-----BEGIN PRIVATE KEY-----\n<paste your key material here - at least 64 characters of base64>\n-----END PRIVATE KEY-----", false},
		{"redaction note", "-----BEGIN PRIVATE KEY-----\n[REDACTED - actual key material removed from this example file on purpose]\n-----END PRIVATE KEY-----", false},
		{"punctuation prose body", "-----BEGIN PRIVATE KEY-----\nInsert your PEM formatted key material here; at least sixty-four (64) chars total!\n-----END PRIVATE KEY-----", false},
		{"truncated body without end", "-----BEGIN PRIVATE KEY-----\n" + body64 + "\n(log line truncated)", false},
		{"body too short", "-----BEGIN PRIVATE KEY-----\nanything\n-----END PRIVATE KEY-----", false},
		{"empty openssh", "-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----", false},
		{"prose mentioning markers without base64", "The config file may contain lines like -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- as delimiters around the base64 material.", false},
		{"note header then lorem ipsum", "-----BEGIN PRIVATE KEY-----\nnote: this is a placeholder example\nlorem ipsum dolor sit amet consetetur sadipscing elitr sed diam nonumy\n-----END PRIVATE KEY-----", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := regexp.MustCompile(rule.Regex)
			if test.match {
				assert.True(t, m.MatchString(test.value),
					"expected true positive to match, got no match")
			} else {
				assert.False(t, m.MatchString(test.value),
					"expected false positive to NOT match, got a match")
			}
		})
	}

	// keywords keep the prefilter usable
	require.Equal(t, []string{"-----begin"}, rule.Keywords)  // normalized by Validate
	require.True(t, strings.HasPrefix(rule.Regex, "(?i)-----BEGIN"))
}
