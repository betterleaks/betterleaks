package rules

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/base"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/stretchr/testify/require"
)

func TestGenericXMLRecords(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) { testGenericXMLRecords(t, engine) })
	}
}

func testGenericXMLRecords(t *testing.T, engine regexp.Engine) {
	const token = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"
	cfg := base.CreateGlobalConfig()
	cfg.Rules = []config.Rule{*GenericCredential(), *GenericPassword(), *GenericUsername()}
	s, err := scan.New(cfg, scan.WithRegexEngine(engine))
	require.NoError(t, err)

	for _, tc := range []struct {
		name, input, rule, value string
		count                    int
	}{
		{"XML element", `<API_KEY>` + token + `</API_KEY>`, "generic-api-key", token, 1},
		{"XML after credential closing tag", "<auth></auth>\n<token>" + token + `</token>`, "generic-api-key", token, 1},
		{"CDATA after credential closing tag", "<secrets></secrets>\n<credential><![CDATA[" + token + `]]></credential>`, "generic-api-key", token, 1},
		{"XML API key closing tag LF", "<API_KEY>" + token + "</API_KEY\n>", "generic-api-key", token, 1},
		{"XML API key closing tag CRLF", "<cfg:API_KEY>" + token + "</cfg:API_KEY \r\n\t>", "generic-api-key", token, 1},
		{"adjacent XML elements", `<API_KEY>` + token + `</API_KEY><API_KEY>` + token + `</API_KEY>`, "generic-api-key", token, 2},
		{"adjacent XML elements with multiline closing tag", "<API_KEY>" + token + "</API_KEY\n><API_KEY>" + token + "</API_KEY>", "generic-api-key", token, 2},
		{"XML two ancestors", "<API_KEYS>\n  <production>\n    <site>" + token + "</site></production></API_KEYS>", "generic-api-key", token, 1},
		{"XML attribute record", `<add key="SERVICE_API_KEY" value="` + token + `"/>`, "generic-api-key", token, 1},
		{"XML name record", `<add name="SERVICE_API_KEY" value="` + token + `"/>`, "generic-api-key", token, 1},
		{"XML labelled text", `<entry key="SERVICE_API_KEY">` + token + `</entry>`, "generic-api-key", token, 1},
		{"XML multiline key/value record", "<add key=\"SERVICE_API_KEY\"\n  value=\"" + token + "\"/>", "generic-api-key", token, 1},
		{"XML CDATA", `<cfg:API_KEYS><cfg:primary><![CDATA[` + token + `]]></cfg:primary></cfg:API_KEYS>`, "generic-api-key", token, 1},
		{"XML authorizer child is not author metadata", `<API_KEYS><authorizer>` + token + `</authorizer></API_KEYS>`, "generic-api-key", token, 1},
		{"XML password", `<PASSWORD><production>hunter2</production></PASSWORD>`, "generic-password", "hunter2", 1},
		{"XML password CDATA", `<PASSWORD><![CDATA[hunter2]]></PASSWORD>`, "generic-password", "hunter2", 1},
		{"XML password CDATA less-than", `<PASSWORD><![CDATA[p4ss<word!]]></PASSWORD>`, "generic-password", "p4ss<word!", 1},
		{"XML password CDATA tag-like text", `<PASSWORD><![CDATA[p4ss</PASSWORD>word!]]></PASSWORD>`, "generic-password", "p4ss</PASSWORD>word!", 1},
		{"XML password CDATA brackets", `<PASSWORD><![CDATA[p4ss]]]word!]]></PASSWORD>`, "generic-password", "p4ss]]]word!", 1},
		{"XML password CDATA trailing brackets", `<PASSWORD><![CDATA[p4ss!]]]]]></PASSWORD>`, "generic-password", "p4ss!]]]", 1},
		{"XML password closing whitespace", "<cfg:PASSWORD><![CDATA[hunter2]]>\n  </cfg:PASSWORD >", "generic-password", "hunter2", 1},
		{"XML password closing tag LF", "<PASSWORD>hunter2</PASSWORD\n>", "generic-password", "hunter2", 1},
		{"XML password CDATA closing tag CRLF", "<PASSWORD><![CDATA[p4ss<word!]]></PASSWORD \r\n\t>", "generic-password", "p4ss<word!", 1},
		{"XML password spaces", `<PASSWORD>correct horse battery staple</PASSWORD>`, "generic-password", "correct horse battery staple", 1},
		{"XML password after closing tag", `<old></old><cfg:DB_PASSWORD>hunter2</cfg:DB_PASSWORD>`, "generic-password", "hunter2", 1},
		{"password containing regex syntax", `<password>w(.*)rd123!</password>`, "generic-password", "w(.*)rd123!", 1},
		{"closed XML element", `<API_KEYS></API_KEYS><other>` + token + `</other>`, "", "", 0},
		{"closed namespaced XML element", `<cfg:SERVICE_API_KEYS></cfg:SERVICE_API_KEYS><other>` + token + `</other>`, "", "", 0},
		{"closed XML password", `<DB_PASSWORD></DB_PASSWORD><other>hunter2</other>`, "", "", 0},
		{"XML shell placeholder", `echo "<password>" | docker login registry.example.com --username <username> --password-stdin`, "", "", 0},
		{"XML URI placeholder", `http://<username>:<password>@hostname:<port>`, "", "", 0},
		{"XML prose placeholder", `use <postgresql_password> to generate a hash for <password_hash>`, "", "", 0},
		{"XML opening tag after text", `<PASSWORD>ordinary text<next>`, "", "", 0},
		{"XML incomplete closing tag", `<PASSWORD>hunter2</`, "", "", 0},
		{"XML CDATA must stop at its terminator", `<PASSWORD><![CDATA[p4ss!]]><other><![CDATA[ignored]]></other></PASSWORD>`, "", "", 0},
		{"XML CDATA cannot swallow markup", `<PASSWORD><![CDATA[p4ss!]]><other>trailing]]></PASSWORD>`, "", "", 0},
		{"XML CDATA short password", `<PASSWORD><![CDATA[p<ss]]></PASSWORD>`, "", "", 0},
		{"XML text cannot swallow markup", `<PASSWORD>p4ss<word!</PASSWORD>`, "", "", 0},
		{"XML API key cannot end at an opening tag", `<API_KEY>` + token + `<SomeType>`, "", "", 0},
		{"HTML password link", `<a href=/docs/generic_password>Generic Password</a>`, "", "", 0},
		{"HTML passwd link", `<a href=/docs/passwd>Database credentials</a>`, "", "", 0},
		{"XML regex capture", `<password>(.+?)</password>`, "", "", 0},
		{"XML regex noncapturing group", `<password>(?:.*)</password>`, "", "", 0},
		{"XML regex character class", `<password>([a-z]+)</password>`, "", "", 0},
		{"XML public certificate", `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + token + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`, "", "", 0},
		{"XML unprefixed public certificate", `<KeyInfo><X509Certificate>` + token + `</X509Certificate></KeyInfo>`, "", "", 0},
		{"XML unrelated attribute", "<API_KEYS\n  fingerprint=\"" + token + "\"/>", "", "", 0},
		{"XML three ancestors", `<API_KEYS><one><two><three>` + token + `</three></two></one></API_KEYS>`, "", "", 0},
		{"XML public key child", `<credentials><public_key>` + token + `</public_key></credentials>`, "", "", 0},
		{"XML replace-with value", `<password>REPLACE_WITH_TOKEN</password>`, "generic-password", "REPLACE_WITH_TOKEN", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := s.ScanString(tc.input)
			require.Len(t, findings, tc.count)
			for _, f := range findings {
				require.Equal(t, tc.rule, f.RuleID)
				require.Equal(t, tc.value, f.Match.Value)
				require.Empty(t, f.Encodings)
			}
		})
	}

	t.Run("keyword fragments in child names", func(t *testing.T) {
		for _, name := range []string{"capital", "turkey", "rapid", "monkey", "accessor", "keyboard"} {
			t.Run(name, func(t *testing.T) {
				require.Empty(t, s.ScanString(`<`+name+`>`+token+`</`+name+`>`))
				require.Empty(t, s.ScanString(`<`+name+`><production>`+token+`</production></`+name+`>`))
				findings := s.ScanString(`<API_KEYS><` + name + `>` + token + `</` + name + `></API_KEYS>`)
				require.Len(t, findings, 1)
				require.Equal(t, token, findings[0].Match.Value)
			})
		}
	})

	t.Run("child metadata remains excluded", func(t *testing.T) {
		for _, name := range []string{"public_key", "access_id", "key_id", "api_version", "author"} {
			require.Empty(t, s.ScanString(`<API_KEYS><turkey><`+name+`>`+token+`</`+name+`></turkey></API_KEYS>`), name)
		}
		require.Empty(t, s.ScanString(`<add key="turkey" value="`+token+`"/>`))
	})
}
