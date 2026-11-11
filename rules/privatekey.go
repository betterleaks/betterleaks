package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "private-key",
	Confidence:  "high",
	Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
	Regex:       `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`,
	Keywords:    []string{"-----BEGIN"},
	Tests: []config.RuleTest{
		Match("validate", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8\nKs14IReLcYgADhoXk56ZzXI=\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8\nKs14IReLcYgADhoXk56ZzXI=\n-----END PRIVATE KEY-----"),
		Match("true positive 1", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3\nyxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=\n-----END RSA PRIVATE KEY-----\n", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3\nyxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=\n-----END RSA PRIVATE KEY-----"),
		Match("bare secret", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic\n=8xQN\n-----END PGP PRIVATE KEY BLOCK-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic\n=8xQN\n-----END PGP PRIVATE KEY BLOCK-----"),
		NoMatch("false positive 1", "-----BEGIN PRIVATE KEY-----\nanything\n-----END PRIVATE KEY-----"),
		NoMatch("false positive 2", "-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----"),
	},
})

// https://en.wikipedia.org/wiki/PKCS_12
var _ = Add(config.Rule{
	ID:          "pkcs12-file",
	Confidence:  "high",
	Description: "Found a PKCS #12 file, which commonly contain bundled private keys.",
	Path:        `(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`,
	Tests: []config.RuleTest{
		{
			Name:       "bare secret",
			Input:      "",
			Attributes: map[string]string{"path": "ToDo/ToDo.UWP/ToDo.UWP_TemporaryKey.pfx"},
			Expect: []config.ExpectedFinding{
				{Secret: ""},
			},
		},
		{
			Name:       "bare secret 2",
			Input:      "",
			Attributes: map[string]string{"path": "cagw_key.P12"},
			Expect: []config.ExpectedFinding{
				{Secret: ""},
			},
		},
		{
			Name:       "bare secret 3",
			Input:      "",
			Attributes: map[string]string{"path": "security/es_certificates/opensearch/es_kibana_client.p12"},
			Expect: []config.ExpectedFinding{
				{Secret: ""},
			},
		},
		{
			Name:       "false positive 1",
			Input:      "",
			Attributes: map[string]string{"path": "doc/typenum/type.P126.html"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 2",
			Input:      "",
			Attributes: map[string]string{"path": "scripts/keeneland/syntest.p1200.sh"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
