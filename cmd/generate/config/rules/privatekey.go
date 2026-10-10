package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func PrivateKey() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "private-key",
		Confidence:  "high",
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex:       `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:(?:[a-zA-Z0-9+/=\s]|\\r|\\n){64,}|\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Za-z0-9-]+,[0-9A-Fa-f]{16,32}\r?\n[a-zA-Z0-9+/=\s]{64,}|(?:\r?\n(?:Version|Comment|Hash|MessageID|Charset|From): [^\n]{0,200})*\r?\n[a-zA-Z0-9+/=\s]{64,})-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`,
		Keywords:    []string{"-----BEGIN"},
	}

	// validate
	tps := []string{`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3
yxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
		// RFC 1421 legacy-encrypted PEMs: Proc-Type/DEK-Info headers sit
		// between the BEGIN marker and the base64 body, and their ":" / ","
		// fall outside the plain base64 class, so they need their own branch.
		`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,8C2C29C4D3B9A1E7

7f3dKq9LmX2vPq8sTU2vBn3kMw9rXy5aQz8cVd1fHg4jKi7oPz6sRt2eWb5mNq1uY0xZr9tKd4fSg7hUz8aVb3nM==
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN ENCRYPTED PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,FB4A3B7CD8E91F05A6C2D4E7F8901234

MIIFLTBXBE9tKbCUBKtJkQNCxUUyFEEtBTvHoloMm1MszT5kA0OBk2ZfS5cV7LpEy
XaQqGWQvNnpWzNslqyP4TQ==
-----END ENCRYPTED PRIVATE KEY-----
`,
		// armored OpenPGP keys carry RFC 4880 armor headers
		// (Version/Comment/...) between the BEGIN marker and the body.
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2.1.11 (GNU/Linux)
Comment: test key

lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
		// JSON-serialized PEMs reach the regex with literal \n escapes
		// (the codec decodes percent/unicode/hex/base64, not JSON escapes).
		`{"key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8\nKs14IReLcYgADhoXk56ZzXI=\n-----END PRIVATE KEY-----"}`,
	} // betterleaks:allow
	fps := []string{
		`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----`,
		// Prose/redaction placeholders must not fire: no base64 body.
		`-----BEGIN PRIVATE KEY-----
<paste your key material here - at least 64 characters of base64>
-----END PRIVATE KEY-----`,
		`-----BEGIN PRIVATE KEY-----
[REDACTED - actual key material removed from this example file on purpose]
-----END PRIVATE KEY-----`,
		// Truncated log line: base64 body but no END terminator.
		`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
(log line truncated)`,
	}
	return utils.Validate(r, tps, fps)
}

func PrivateKeyPKCS12File() *config.Rule {
	// https://en.wikipedia.org/wiki/PKCS_12
	r := config.Rule{
		ID:          "pkcs12-file",
		Confidence:  "high",
		Description: "Found a PKCS #12 file, which commonly contain bundled private keys.",
		Path:        `(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`,
	}

	// validate
	tps := map[string]string{
		"security/es_certificates/opensearch/es_kibana_client.p12": "",
		"cagw_key.P12": "",
		"ToDo/ToDo.UWP/ToDo.UWP_TemporaryKey.pfx": "",
	}
	fps := map[string]string{
		"doc/typenum/type.P126.html":         "",
		"scripts/keeneland/syntest.p1200.sh": "",
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
