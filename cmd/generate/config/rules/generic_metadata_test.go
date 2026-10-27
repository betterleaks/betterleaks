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

func TestGenericMetadata(t *testing.T) {
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
				{"schema type", "schema.json", `{"password":{"Type":"string"}}`, 0},
				{"schema return type", "schema.json", `{"password":{"ReturnType":"System.Boolean"}}`, 0},
				{"schema shape", "schema.json", `{"password":{"shape":"SensitiveString"}}`, 0},
				{"nested schema", "schema.json", `{"password":{"schema":{"type":"string"}}}`, 0},
				{"array schema", "schema.json", `{"password":[{"type":"string"}]}`, 0},
				{"schema reference", "template.json", `{"Password":{"Ref":"DatabasePassword"}}`, 0},
				{"XML schema", "schema.xml", `<PASSWORD><cfg:Type>string</cfg:Type></PASSWORD>`, 0},
				{"XML nested schema", "schema.xml", `<PASSWORD><schema><Type>string</Type></schema></PASSWORD>`, 0},
				{"literal type word", "settings.json", `{"password":"string"}`, 1},
				{"nested literal type word", "settings.json", `{"password":{"production":"string"}}`, 1},
				{"schema default password", "schema.json", `{"password":{"default":"hunter2"}}`, 1},
				{"metadata text in literal", "settings.php", `password = 'prefix{"Type":"string"}suffix';`, 1},
				{"metadata text in CDATA", "settings.xml", `<PASSWORD><![CDATA[prefix<Type>string</Type>suffix]]></PASSWORD>`, 1},
				{"metadata word inside service name", "settings.json", `{"password":{"prototype":"hunter2"}}`, 1},
				{"benchmark elapsed", "bench.json", `{"generic-password":{"elapsed":"12.34s"}}`, 0},
				{"nested benchmark duration", "bench.json", `{"password":{"stats":{"duration":"1m30.5s"}}}`, 0},
				{"XML benchmark average", "bench.xml", `<password><average>42.5µs</average></password>`, 0},
				{"ordinary duration password", "settings.json", `{"password":"12.34s"}`, 1},
				{"duration as service password", "settings.json", `{"password":{"production":"12.34s"}}`, 1},
				{"timing name with literal password", "settings.json", `{"password":{"elapsed":"hunter2"}}`, 1},
				{"timing text in literal", "settings.php", `password = 'prefix{"elapsed":"12.34s"}suffix';`, 1},
				{"schema member documentation", "docs.php", `'Password' => ['base' => NULL, 'refs' => ['Login$password' => '<p>The password for this account.</p>',]],`, 0},
				{"schema later member documentation", "docs.php", `'refs' => ['Login$user' => '<p>Text with [brackets] and \'quotes\'.</p>', 'Login$password' => '<p>The password for this account.</p>',],`, 0},
				{"multiline schema documentation", "docs.php", "'refs' => [\n  'Login$user' => NULL,\n  'Login$password' => '<p>The password for this account.</p>',\n],", 0},
				{"literal schema example", "docs.php", `'refs' => ['Login$password' => 'hunter2'],`, 1},
				{"HTML password", "settings.php", `$password = '<p>correct horse battery staple</p>';`, 1},
				{"HTML password after schema", "docs.php", `'refs' => ['Login$user' => '<p>Documentation.</p>'], 'password' => '<p>correct horse battery staple</p>',`, 1},
				{"HTML password in nested credentials", "docs.php", `'refs' => ['credentials' => ['password' => '<p>correct horse battery staple</p>']],`, 1},
				{"plain passphrase in refs", "settings.php", `'refs' => ['password' => 'correct horse battery staple'],`, 1},
				{"HTML password in refs", "settings.php", `'refs' => ['password' => '<p>correct horse battery staple</p>'],`, 1},
				{"schema default is still a credential", "docs.php", `'refs' => ['Login$user' => NULL], 'defaults' => ['password' => 'replace_me'],`, 1},
				{"spaced key ID", "docs.html", `Key ID: <code>` + token + `</code>`, 0},
				{"tabbed key ID", "docs.html", "Key\t ID: <code>" + token + "</code>", 0},
				{"client ID child", "settings.json", `{"credentials":{"client_id":"` + token + `"}}`, 0},
				{"component GUID", "components.json", `{"AccessClientComponents":{"1.0.0.0":{"Guid":"` + token + `"}}}`, 0},
				{"RSA public modulus", "key.xml", `<RSAKeyValue><Modulus>` + token + `</Modulus></RSAKeyValue>`, 0},
				{"RSA private component", "key.xml", `<RSAKeyValue><D>` + token + `</D></RSAKeyValue>`, 1},
				{"client secret child", "settings.json", `{"credentials":{"client_secret":"` + token + `"}}`, 1},
				{"GUID word inside service name", "settings.json", `{"API_KEYS":{"guide":"` + token + `"}}`, 1},
				{"public key version example", "docs.json", `{"description":"<p>The current version of the public key. For example: <code>` + token + `</code>.</p>"}`, 0},
				{"public key update version example", "docs.json", `{"description":"<p>The current version of the update public key result. For example: <code>` + token + `</code>.</p>"}`, 0},
				{"public key ETag example", "docs.html", `ETag for the public key. For example: <code>` + token + `</code>`, 0},
				{"ordinary example key", "docs.html", `API key. For example: <code>` + token + `</code>`, 1},
				{"private key example", "docs.html", `The current version of the private key. For example: <code>` + token + `</code>`, 1},
				{"assignment after public key docs", "docs.html", `The current version of the public key. For example: <code>` + token + `</code>. API_KEY="` + token + `"`, 1},
				{"unrelated public key description", "settings.json", `{"description":"version of the public", "key":"` + token + `"}`, 1},
				{"unrelated public key prose", "docs.html", `"version of the public" Another key. For example: <code>` + token + `</code>`, 1},
				{"signature type", "CallMap.php", `'AMQPConnection::setPassword' => ['bool', 'password'=>'string'],`, 0},
				{"signature union", "CallMap.php", `'connect' => ['resource|false', 'host'=>'string', 'password'=>'string'],`, 0},
				{"signature class", "CallMap.php", `'setPassword' => ['Couchbase\PasswordAuthenticator', 'password'=>'string'],`, 0},
				{"signature empty return", "CallMap.php", `'setPassword' => ['', 'password'=>'string'],`, 0},
				{"ordinary PHP literal", "settings.php", `$password = 'string';`, 1},
				{"PHP credential map", "settings.php", `'database' => ['mysql', 'password'=>'string'],`, 1},
				{"PHP password argument default", "settings.php", `function connect($password = 'string') {}`, 1},
				{"translation", "app/languages/en/messages.php", "  'Password' => 'Enter your password',", 0},
				{"translation phrase", "app/languages/en/messages.php", "  'Reset Password' => 'Reset your password',", 0},
				{"translation service label", "app/lang/en.php", "  'SMTP Password' => 'Mail server password',", 0},
				{"Windows translation path", `app\languages\en\messages.php`, "  'Password' => 'Enter your password',", 0},
				{"translation without path", "", "  'Password' => 'Enter your password',", 1},
				{"ordinary PHP map", "app/settings.php", "  'Password' => 'Enter your password',", 1},
				{"assignment in translation path", "app/lang/en.php", `$password = 'hunter2';`, 1},
				{"inline credentials in translation path", "app/lang/en.php", `$credentials = ['password' => 'hunter2'];`, 1},
				{"multiline credentials in translation path", "app/lang/en.php", "$credentials = [\n  'password' => 'hunter2',\n];", 1},
				{"credential label in translation path", "app/lang/en.php", "$credentials = [\n  'SMTP Password' => 'hunter2',\n];", 1},
				{"credentials translation is still text", "app/lang/en.php", "'credentials' => 'Credentials',\n'Password' => 'Enter your password',", 0},
				{"replace-me credential", "settings.yml", "credentials: {\nusername: alice\npassword: replace_me\n}", 1},
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
