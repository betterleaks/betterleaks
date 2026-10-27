package rules

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/base"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestGenericJSONRecords(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) { testGenericJSONRecords(t, engine) })
	}
}

func testGenericJSONRecords(t *testing.T, engine regexp.Engine) {
	const token = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"
	cfg := base.CreateGlobalConfig()
	cfg.Rules = []config.Rule{*GenericCredential(), *GenericPassword(), *GenericUsername()}
	s, err := scan.New(cfg, scan.WithRegexEngine(engine))
	require.NoError(t, err)

	for _, tc := range []struct {
		name, input, rule, value string
		count                    int
	}{
		{"API name", `{"name":"SERVICE_API_KEY","value":"` + token + `"}`, "generic-api-key", token, 1},
		{"API key", `{"key":"SERVICE_API_KEY","value":"` + token + `"}`, "generic-api-key", token, 1},
		{"bare fields", `{name: "SERVICE_API_KEY", value: "` + token + `"}`, "generic-api-key", token, 1},
		{"multiline", "{\n  \"name\": \"SERVICE_API_KEY\",\n  \"value\": \"" + token + "\"\n}", "generic-api-key", token, 1},
		{"password", `{"name":"DB_PASSWORD","value":"hunter2"}`, "generic-password", "hunter2", 1},
		{"password key", `{"key":"DB_PASSWORD","value":"hunter2"}`, "generic-password", "hunter2", 1},
		{"password spaces", `{"name":"DB_PASSWORD","value":"correct horse battery staple"}`, "generic-password", "correct horse battery staple", 1},
		{"repeated records", `[{"name":"SERVICE_API_KEY","value":"` + token + `"},{"name":"SERVICE_API_KEY","value":"` + token + `"}]`, "generic-api-key", token, 2},
		{"ordinary assignment", `API_KEY="` + token + `"`, "generic-api-key", token, 1},
		{"value on next line", "API_KEY =\n  \"" + token + "\"", "generic-api-key", token, 1},
		{"operator on next line", "\"API_KEY\"\n  : \"" + token + "\"", "generic-api-key", token, 1},
		{"indented operator on next line", "SERVICE_KEY\r\n            = \"" + token + "\"", "generic-api-key", token, 1},
		{"indented map", "{\"API_KEYS\": {\n        \"news24\": \"" + token + "\"}}", "generic-api-key", token, 1},
		{"two ancestors", `{"API_KEYS":{"production":{"site":"` + token + `"}}}`, "generic-api-key", token, 1},
		{"authorizer child is not author metadata", `{"API_KEYS":{"authorizer":"` + token + `"}}`, "generic-api-key", token, 1},
		{"first sibling only", `{"API_KEYS":{"first":"` + token + `","second":"a8F3kW6pR1zN9qD4vT7mB2xH5sJ0cYLu"}}`, "generic-api-key", token, 1},
		{"array of maps", `{"API_KEYS":[{"site":"` + token + `"}]}`, "generic-api-key", token, 1},
		{"prose before map", "{\"description\":\"Credential label is two ancestors above the value\",\n      \"API_KEYS\":{\"production\":{\"site\":\"" + token + "\"}}}", "generic-api-key", token, 1},
		{"XML element", `<API_KEY>` + token + `</API_KEY>`, "generic-api-key", token, 1},
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
		{"nested password", "{\"DB_PASSWORD\":{\n        \"production\":\"hunter2\"}}", "generic-password", "hunter2", 1},
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
		{"certificate outside match", `API_KEY="` + token + `" <ds:X509Certificate>public</ds:X509Certificate>`, "generic-api-key", token, 1},
		{"unquoted password punctuation", `password=hunt]er<2`, "generic-password", "hunt]er<2", 1},
		{"direct secret before value field", `{"key":"` + token + `KEY","value":"unrelated"}`, "generic-api-key", token + "KEY", 1},
		{"ordinary password", `password="hunter2"`, "generic-password", "hunter2", 1},
		{"CDATA terminator in ordinary password", `password="p4ss]]>word!"`, "generic-password", "p4ss]]>word!", 1},
		{"replacement is not an instruction", `password="replacement123!"`, "generic-password", "replacement123!", 1},
		{"replace-me prefix is not a word", `password="replace_meadow123!"`, "generic-password", "replace_meadow123!", 1},
		{"replace inside a password", `password="never_replace_me_123!"`, "generic-password", "never_replace_me_123!", 1},
		{"other object", `[{"name":"SERVICE_API_KEY"},{"value":"` + token + `"}]`, "", "", 0},
		{"closed map", `{"API_KEYS":{},"other":"` + token + `"}`, "", "", 0},
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
		{"C++ template expression", `api_key = ` + token + `<SomeType>{};`, "", "", 0},
		{"XML API key cannot end at an opening tag", `<API_KEY>` + token + `<SomeType>`, "", "", 0},
		{"HTML password link", `<a href=/docs/generic_password>Generic Password</a>`, "", "", 0},
		{"HTML passwd link", `<a href=/docs/passwd>Database credentials</a>`, "", "", 0},
		{"XML regex capture", `<password>(.+?)</password>`, "", "", 0},
		{"XML regex noncapturing group", `<password>(?:.*)</password>`, "", "", 0},
		{"XML regex character class", `<password>([a-z]+)</password>`, "", "", 0},
		{"XML public certificate", `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + token + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`, "", "", 0},
		{"XML unprefixed public certificate", `<KeyInfo><X509Certificate>` + token + `</X509Certificate></KeyInfo>`, "", "", 0},
		{"YAML unrelated UID", "selfLink: /secrets/production-secret\n  uid: 72c1fa06-b4de-437c-a983-8f2ad90e6215", "", "", 0},
		{"YAML unrelated operation", "tags:\n  - keys\noperationId: " + token, "", "", 0},
		{"YAML descriptive token", "description: A trigger token\n  example: " + token, "", "", 0},
		{"unrelated quoted field", "API_KEY\n  \"id\": \"" + token + "\"", "", "", 0},
		{"unrelated assignment", "# OAuth tokens\nCLIENT_ID=" + token, "", "", 0},
		{"XML unrelated attribute", "<API_KEYS\n  fingerprint=\"" + token + "\"/>", "", "", 0},
		{"unrelated comma field", "key\n  - vendor,device-9062", "", "", 0},
		{"unrelated field after blank line", "secret\n\n uid: " + token, "", "", 0},
		{"operator after blank lines", "api\n\n\n\n= \"" + token + `"`, "", "", 0},
		{"operator after CRLF blank line", "API_KEY\r\n  \r\n  = \"" + token + `"`, "", "", 0},
		{"assignment after blank-line comment", "// configure key\n\n\nserviceKey := \"" + token + `"`, "generic-api-key", token, 1},
		{"empty first value", `{"API_KEYS":{"first":"","second":"` + token + `"}}`, "", "", 0},
		{"three ancestors", `{"API_KEYS":{"one":{"two":{"three":"` + token + `"}}}}`, "", "", 0},
		{"XML three ancestors", `<API_KEYS><one><two><three>` + token + `</three></two></one></API_KEYS>`, "", "", 0},
		{"nested public key", `{"PUBLIC_KEY":{"production":"` + token + `"}}`, "", "", 0},
		{"public key child", `{"credentials":{"public_key":"` + token + `"}}`, "", "", 0},
		{"access ID child", `{"credentials":{"access_id":"` + token + `"}}`, "", "", 0},
		{"key ID child", `{"API_KEYS":{"key_id":"` + token + `"}}`, "", "", 0},
		{"nested metadata stays excluded", `{"API_KEYS":{"primary_key":{"access_id":"` + token + `"}}}`, "", "", 0},
		{"XML public key child", `<credentials><public_key>` + token + `</public_key></credentials>`, "", "", 0},
		{"YAML child field", "PASSWORD:\n  vault: production/database/password", "", "", 0},
		{"YAML angle placeholder", "PASSWORD: <personal_access_token>\n  TWINE_USERNAME: gitlab-ci-token", "", "", 0},
		{"Ruby secret reference", `PASSWORD: { gitlab_secrets_manager: { name: "password", source: "group/some_group" } }`, "", "", 0},
		{"reversed record unsupported", `{"value":"` + token + `","name":"SERVICE_API_KEY"}`, "", "", 0},
		{"unrelated name", `{"name":"DEPLOYMENT_ID","value":"` + token + `"}`, "", "", 0},
		{"public key", `{"name":"PUBLIC_KEY","value":"` + token + `"}`, "", "", 0},
		{"public key record label", `{"key":"PUBLIC_KEY","value":"` + token + `"}`, "", "", 0},
		{"metadata name", `{"name":"API_VERSION","value":"` + token + `"}`, "", "", 0},
		{"placeholder", `{"name":"DB_PASSWORD","value":"${DB_PASSWORD}"}`, "", "", 0},
		{"XML replace-with placeholder", `<password>REPLACE_WITH_TOKEN</password>`, "", "", 0},
		{"replace-me placeholder", `password="replace_me"`, "", "", 0},
		{"replace-with spaced placeholder", `password="Replace With Your Password"`, "", "", 0},
		{"replace-me hyphenated placeholder", `password="REPLACE-ME"`, "", "", 0},
		{"replace-with dotted placeholder", `password="replace.with.token"`, "", "", 0},
		{"JSON replacement placeholder", `{"name":"DB_PASSWORD","value":"REPLACE_WITH_TOKEN"}`, "", "", 0},
		{"password hash", `{"name":"DB_PASSWORD","value":"$2b$12$abcdefghijklmnopqrstuu"}`, "", "", 0},
		{"empty", `{"name":"SERVICE_API_KEY","value":""}`, "", "", 0},
		{"null", `{"name":"SERVICE_API_KEY","value":null}`, "", "", 0},
		{"boolean password", `{"name":"DB_PASSWORD","value":false}`, "", "", 0},
		{"object password", `{"name":"DB_PASSWORD","value":{"ref":"service"}}`, "", "", 0},
		{"password expression", `{"name":"DB_PASSWORD","value":process.env.DB_PASSWORD}`, "", "", 0},
		{"reference", `{"name":"SERVICE_API_KEY","valueFrom":{"secretKeyRef":{"name":"service","key":"token"}}}`, "", "", 0},
		{"truncated outer object", `{"name":"SERVICE_API_KEY","value":"` + token + `"`, "generic-api-key", token, 1},
		{"embedded record", `const settings = {name: "SERVICE_API_KEY", value: "` + token + `"};`, "generic-api-key", token, 1},
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
				// These words do not identify credentials on their own.
				require.Empty(t, s.ScanString(name+`="`+token+`"`))
				require.Empty(t, s.ScanString(`{"`+name+`":{"production":"`+token+`"}}`))
				// An explicit credential parent supplies that context.
				for _, input := range []string{
					`{"API_KEYS":{"` + name + `":"` + token + `"}}`,
					`{"API_KEYS":[{"production":{"` + name + `":"` + token + `"}}]}`,
					`<API_KEYS><` + name + `>` + token + `</` + name + `></API_KEYS>`,
				} {
					findings := s.ScanString(input)
					require.Len(t, findings, 1, input)
					require.Equal(t, token, findings[0].Match.Value)
				}
			})
		}
	})

	t.Run("child metadata remains excluded", func(t *testing.T) {
		for _, name := range []string{"public_key", "access_id", "key_id", "api_version", "author"} {
			require.Empty(t, s.ScanString(`{"API_KEYS":{"turkey":{"`+name+`":"`+token+`"}}}`), name)
			require.Empty(t, s.ScanString(`<API_KEYS><turkey><`+name+`>`+token+`</`+name+`></turkey></API_KEYS>`), name)
		}
		// A record's label must still be checked even when it follows "key".
		require.Empty(t, s.ScanString(`{"key":"turkey","value":"`+token+`"}`))
		require.Empty(t, s.ScanString(`<add key="turkey" value="`+token+`"/>`))
	})

	t.Run("author metadata and authorization", func(t *testing.T) {
		// Preserve author fields without excluding authorization-related names.
		for _, field := range []string{"author", "AUTHOR", "author_id", "author_name", "author-email", "author.name", "authorId", "authorName", "authorEmail", "authorLogin", "authorityFileId", "AUTHORED_SHA"} {
			require.Empty(t, s.ScanString(field+`="`+token+`"`), field)
		}
		for _, field := range []string{"authorizer", "AUTHORIZER", "authorizer_key", "authorization", "authorizationToken", "authorisation", "authoriser"} {
			findings := s.ScanString(field + `="` + token + `"`)
			require.Len(t, findings, 1, field)
			require.Equal(t, token, findings[0].Match.Value)
		}
	})

	t.Run("child token confidence", func(t *testing.T) {
		for _, input := range []string{
			`{"credentials":{"worker_token":"` + token + `"}}`,
			`{"credentials":{"turkey":{"worker_token":"` + token + `"}}}`,
		} {
			findings := s.ScanString(input)
			require.Len(t, findings, 1)
			require.Equal(t, token, findings[0].Match.Value)
			require.Equal(t, "medium", findings[0].Confidence)
		}
	})

	// A preceding credential word must neither consume nor suppress an
	// independent assignment. Exercise syntax and keywords without providers.
	t.Run("assignment after credential comment", func(t *testing.T) {
		for _, keyword := range []string{"key", "secret", "token", "auth", "credential", "api"} {
			for _, operator := range []string{"=", ":=", ":", "=>"} {
				for _, newline := range []string{"\n", "\r\n"} {
					input := "// configure " + keyword + newline + "serviceKey " + operator + ` "` + token + `"`
					findings := s.ScanString(input)
					require.Len(t, findings, 1, input)
					require.Equal(t, token, findings[0].Match.Value)
					require.Equal(t, 2, findings[0].Location.StartLine, input)
				}
			}
		}
	})

	t.Run("decoded record", func(t *testing.T) {
		s, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithMaxDecodeDepth(1))
		require.NoError(t, err)
		input := `{"name":"SERVICE_API_KEY","value":"` + token + `"}`
		findings := s.ScanString(base64.StdEncoding.EncodeToString([]byte(input)))
		require.Len(t, findings, 1)
		require.Equal(t, token, findings[0].Match.Value)
		require.Equal(t, []string{"base64"}, findings[0].Encodings)
	})

	t.Run("decoded child names", func(t *testing.T) {
		s, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithMaxDecodeDepth(1))
		require.NoError(t, err)
		input := `{"API_KEYS":{"turkey":"` + token + `"}}`
		findings := s.ScanString(base64.StdEncoding.EncodeToString([]byte(input)))
		require.Len(t, findings, 1)
		require.Equal(t, token, findings[0].Match.Value)
		require.Equal(t, []string{"base64"}, findings[0].Encodings)
		input = `{"credentials":{"public_key":"` + token + `"}}`
		require.Empty(t, s.ScanString(base64.StdEncoding.EncodeToString([]byte(input))))
	})

	t.Run("nested password in code", func(t *testing.T) {
		for _, tc := range []struct {
			raw   string
			count int
		}{
			{`const cfg = {"DB_PASSWORD":{"prod":"hunter2"}};`, 1},
			{`const cfg = {password:{type: string}};`, 0},
			{`password = process.env.DB_PASSWORD`, 0},
		} {
			summary, err := s.Scan(t.Context(), genericFragment{Raw: tc.raw, Attributes: map[string]string{sources.AttrPath: "settings.js"}}, nil)
			require.NoError(t, err)
			require.Equal(t, tc.count, summary.Findings, tc.raw)
		}
	})
}

type genericFragment sources.Fragment

func (f genericFragment) Fragments(_ context.Context, yield sources.FragmentsFunc) error {
	return yield(sources.Fragment(f), nil)
}
