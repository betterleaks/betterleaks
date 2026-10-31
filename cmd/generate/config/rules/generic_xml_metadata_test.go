package rules

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/base"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestGenericXMLMetadata(t *testing.T) {
	const token = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			cfg := base.CreateGlobalConfig()
			cfg.Rules = []config.Rule{*GenericCredential(), *GenericPassword(), *GenericUsername()}
			s, err := scan.New(cfg, scan.WithRegexEngine(engine))
			require.NoError(t, err)
			for _, tc := range []struct {
				name, path, raw string
				count           int
			}{
				{"XML schema", "schema.xml", `<PASSWORD><cfg:Type>string</cfg:Type></PASSWORD>`, 0},
				{"XML schema with attributes", "schema.xml", `<PASSWORD xmlns="urn:cfg"><Type source='schema'>string</Type></PASSWORD>`, 0},
				{"XML nested schema", "schema.xml", `<PASSWORD><schema><Type>string</Type></schema></PASSWORD>`, 0},
				{"metadata text in CDATA", "settings.xml", `<PASSWORD><![CDATA[prefix<Type>string</Type>suffix]]></PASSWORD>`, 1},
				{"XML benchmark average", "bench.xml", `<password><average>42.5µs</average></password>`, 0},
				{"XML benchmark with attributes", "bench.xml", "<password\n suite='test'><average unit='us'>42.5µs</average></password>", 0},
				{"spaced key ID", "docs.html", `Key ID: <code>` + token + `</code>`, 0},
				{"tabbed key ID", "docs.html", "Key\t ID: <code>" + token + "</code>", 0},
				{"RSA public modulus", "key.xml", `<RSAKeyValue><Modulus>` + token + `</Modulus></RSAKeyValue>`, 0},
				{"RSA public modulus with attributes", "key.xml", `<RSAKeyValue xmlns="urn:cfg"><Modulus format='base64'>` + token + `</Modulus></RSAKeyValue>`, 0},
				{"certificate with attributes", "key.xml", `<KeyInfo xmlns="urn:cfg"><X509Certificate format='base64'>` + token + `</X509Certificate></KeyInfo>`, 0},
				{"RSA private component", "key.xml", `<RSAKeyValue><D>` + token + `</D></RSAKeyValue>`, 1},
				{"public key version example", "docs.json", `{"description":"<p>The current version of the public key. For example: <code>` + token + `</code>.</p>"}`, 0},
				{"public key update version example", "docs.json", `{"description":"<p>The current version of the update public key result. For example: <code>` + token + `</code>.</p>"}`, 0},
				{"public key ETag example", "docs.html", `ETag for the public key. For example: <code>` + token + `</code>`, 0},
				{"ordinary example key", "docs.html", `API key. For example: <code>` + token + `</code>`, 1},
				{"private key example", "docs.html", `The current version of the private key. For example: <code>` + token + `</code>`, 1},
				{"assignment after public key docs", "docs.html", `The current version of the public key. For example: <code>` + token + `</code>. API_KEY="` + token + `"`, 1},
				{"unrelated public key prose", "docs.html", `"version of the public" Another key. For example: <code>` + token + `</code>`, 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					summary, err := s.Scan(t.Context(), genericFragment{
						Raw:        tc.raw,
						Attributes: map[string]string{sources.AttrPath: tc.path},
					}, nil)
					require.NoError(t, err)
					require.Equal(t, tc.count, summary.Findings)
				})
			}
		})
	}
}
