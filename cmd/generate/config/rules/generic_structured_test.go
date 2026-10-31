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
		{"record label with digits", `{"key":"S3_API_KEY","value":"` + token + `"}`, "generic-api-key", token, 1},
		{"record label with version", `{"key":"OAUTH2_CLIENT_SECRET","value":"` + token + `"}`, "generic-api-key", token, 1},
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
		{"value after scalar siblings", "{\n  \"credential\": {\n    \"score\": 42,\n    \"category\": \"fixture\",\n    \"value\": \"" + token + "\"\n  }\n}", "generic-api-key", token, 1},
		{"value after five siblings", `{"credential":{"score":42,"category":"fixture","enabled":true,"expires":null,"ratio":-1.25e-3,"value":"` + token + `"}}`, "generic-api-key", token, 1},
		{"five siblings with CRLF", "{\"credential\": {\r\n  \"score\": 42,\r\n  \"category\": \"fixture\",\r\n  \"enabled\": true,\r\n  \"expires\": null,\r\n  \"ratio\": -1.25e-3,\r\n  \"value\": \"" + token + "\"\r\n}}", "generic-api-key", token, 1},
		{"explicit value takes precedence over metadata", `{"credential":{"checksum":"a8F3kW6pR1zN9qD4vT7mB2xH5sJ0cYLu","value":"` + token + `"}}`, "generic-api-key", token, 1},
		{"value after long metadata string", `{"credential":{"category":"security incident classification","value":"` + token + `"}}`, "generic-api-key", token, 1},
		{"metadata quotes and punctuation", `{"credential":{"description":"a comma, a brace } and an escaped quote \"","value":"` + token + `"}}`, "generic-api-key", token, 1},
		{"metadata cannot skip unterminated string", `{"credential":{"category":"fixture,"value":"` + token + `"}}`, "", "", 0},
		{"metadata identifier is not the secret", `{"credential":{"client_id":"public","key_id":42,"value":"` + token + `"}}`, "generic-api-key", token, 1},
		{"value after nested siblings", `{"credentials":{"production":{"score":42,"category":"fixture","value":"` + token + `"}}}`, "generic-api-key", token, 1},
		{"value in array record", `{"credentials":[{"score":42,"value":"` + token + `"}]}`, "generic-api-key", token, 1},
		{"password value after metadata", `{"password":{"type":"string","score":42,"value":"hunter2"}}`, "generic-password", "hunter2", 1},
		{"password value after five siblings", `{"password":{"score":42,"category":"fixture","enabled":false,"expires":null,"ratio":1e3,"value":"hunter2"}}`, "generic-password", "hunter2", 1},
		{"value after six siblings unsupported", `{"credential":{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"value":"` + token + `"}}`, "", "", 0},
		{"metadata cannot cross object", `{"credential":{"score":42},"value":"` + token + `"}`, "", "", 0},
		{"metadata cannot cross array entry", `[{"credential":{"score":42}},{"value":"` + token + `"}]`, "", "", 0},
		{"metadata object unsupported", `{"credential":{"details":{"score":42},"value":"` + token + `"}}`, "", "", 0},
		{"metadata array unsupported", `{"credential":{"scores":[42],"value":"` + token + `"}}`, "", "", 0},
		{"metadata requires value field", `{"credential":{"score":42,"category":"fixture","other":"` + token + `"}}`, "", "", 0},
		{"metadata requires credential parent", `{"deployment":{"score":42,"category":"fixture","value":"` + token + `"}}`, "", "", 0},
		{"metadata preserves public parent exclusion", `{"public_key":{"score":42,"value":"` + token + `"}}`, "", "", 0},
		{"metadata preserves public child exclusion", `{"credential":{"public_key":{"score":42,"value":"` + token + `"}}}`, "", "", 0},
		{"metadata preserves value filters", `{"credential":{"score":42,"value":"someplaceholder"}}`, "", "", 0},
		{"authorizer child is not author metadata", `{"API_KEYS":{"authorizer":"` + token + `"}}`, "generic-api-key", token, 1},
		{"first sibling only", `{"API_KEYS":{"first":"` + token + `","second":"a8F3kW6pR1zN9qD4vT7mB2xH5sJ0cYLu"}}`, "generic-api-key", token, 1},
		{"array of maps", `{"API_KEYS":[{"site":"` + token + `"}]}`, "generic-api-key", token, 1},
		{"prose before map", "{\"description\":\"Credential label is two ancestors above the value\",\n      \"API_KEYS\":{\"production\":{\"site\":\"" + token + "\"}}}", "generic-api-key", token, 1},
		{"nested password", "{\"DB_PASSWORD\":{\n        \"production\":\"hunter2\"}}", "generic-password", "hunter2", 1},
		{"certificate outside match", `API_KEY="` + token + `" <ds:X509Certificate>public</ds:X509Certificate>`, "generic-api-key", token, 1},
		{"unquoted password punctuation", `password=hunt]er<2`, "generic-password", "hunt]er<2", 1},
		{"direct secret before value field", `{"key":"` + token + `KEY","value":"unrelated"}`, "generic-api-key", token + "KEY", 1},
		{"ordinary password", `password="hunter2"`, "generic-password", "hunter2", 1},
		{"metadata syntax inside password stays literal", `password='prefix{"score":42,"value":"hunter2"}suffix'`, "generic-password", `prefix{"score":42,"value":"hunter2"}suffix`, 1},
		{"CDATA terminator in ordinary password", `password="p4ss]]>word!"`, "generic-password", "p4ss]]>word!", 1},
		{"replacement is not an instruction", `password="replacement123!"`, "generic-password", "replacement123!", 1},
		{"replace-me prefix is not a word", `password="replace_meadow123!"`, "generic-password", "replace_meadow123!", 1},
		{"replace inside a password", `password="never_replace_me_123!"`, "generic-password", "never_replace_me_123!", 1},
		{"other object", `[{"name":"SERVICE_API_KEY"},{"value":"` + token + `"}]`, "", "", 0},
		{"closed map", `{"API_KEYS":{},"other":"` + token + `"}`, "", "", 0},
		{"C++ template expression", `api_key = ` + token + `<SomeType>{};`, "", "", 0},
		{"YAML unrelated UID", "selfLink: /secrets/production-secret\n  uid: 72c1fa06-b4de-437c-a983-8f2ad90e6215", "", "", 0},
		{"YAML unrelated operation", "tags:\n  - keys\noperationId: " + token, "", "", 0},
		{"YAML descriptive token", "description: A trigger token\n  example: " + token, "", "", 0},
		{"unrelated quoted field", "API_KEY\n  \"id\": \"" + token + "\"", "", "", 0},
		{"unrelated assignment", "# OAuth tokens\nCLIENT_ID=" + token, "", "", 0},
		{"unrelated comma field", "key\n  - vendor,device-9062", "", "", 0},
		{"unrelated field after blank line", "secret\n\n uid: " + token, "", "", 0},
		{"operator after blank lines", "api\n\n\n\n= \"" + token + `"`, "", "", 0},
		{"operator after CRLF blank line", "API_KEY\r\n  \r\n  = \"" + token + `"`, "", "", 0},
		{"assignment after blank-line comment", "// configure key\n\n\nserviceKey := \"" + token + `"`, "generic-api-key", token, 1},
		{"empty first value", `{"API_KEYS":{"first":"","second":"` + token + `"}}`, "", "", 0},
		{"three ancestors", `{"API_KEYS":{"one":{"two":{"three":"` + token + `"}}}}`, "", "", 0},
		{"nested public key", `{"PUBLIC_KEY":{"production":"` + token + `"}}`, "", "", 0},
		{"public key child", `{"credentials":{"public_key":"` + token + `"}}`, "", "", 0},
		{"access ID child", `{"credentials":{"access_id":"` + token + `"}}`, "", "", 0},
		{"key ID child", `{"API_KEYS":{"key_id":"` + token + `"}}`, "", "", 0},
		{"nested metadata stays excluded", `{"API_KEYS":{"primary_key":{"access_id":"` + token + `"}}}`, "", "", 0},
		{"YAML child field", "PASSWORD:\n  vault: production/database/password", "", "", 0},
		{"YAML angle placeholder", "PASSWORD: <personal_access_token>\n  TWINE_USERNAME: gitlab-ci-token", "", "", 0},
		{"Ruby secret reference", `PASSWORD: { gitlab_secrets_manager: { name: "password", source: "group/some_group" } }`, "", "", 0},
		{"reversed record unsupported", `{"value":"` + token + `","name":"SERVICE_API_KEY"}`, "", "", 0},
		{"unrelated name", `{"name":"DEPLOYMENT_ID","value":"` + token + `"}`, "", "", 0},
		{"public key", `{"name":"PUBLIC_KEY","value":"` + token + `"}`, "", "", 0},
		{"public key record label", `{"key":"PUBLIC_KEY","value":"` + token + `"}`, "", "", 0},
		{"metadata name", `{"name":"API_VERSION","value":"` + token + `"}`, "", "", 0},
		{"placeholder", `{"name":"DB_PASSWORD","value":"${DB_PASSWORD}"}`, "", "", 0},
		{"replace-me value", `password="replace_me"`, "generic-password", "replace_me", 1},
		{"replace-with spaced value", `password="Replace With Your Password"`, "generic-password", "Replace With Your Password", 1},
		{"replace-me hyphenated value", `password="REPLACE-ME"`, "generic-password", "REPLACE-ME", 1},
		{"replace-with dotted value", `password="replace.with.token"`, "generic-password", "replace.with.token", 1},
		{"JSON replacement value", `{"name":"DB_PASSWORD","value":"REPLACE_WITH_TOKEN"}`, "generic-password", "REPLACE_WITH_TOKEN", 1},
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
		}
		// A record's label must still be checked even when it follows "key".
		require.Empty(t, s.ScanString(`{"key":"turkey","value":"`+token+`"}`))
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
		input = `{"credential":{"score":42,"category":"fixture","value":"` + token + `"}}`
		findings = s.ScanString(base64.StdEncoding.EncodeToString([]byte(input)))
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
