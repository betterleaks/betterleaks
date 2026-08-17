package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericCredentialURI() *config.Rule {
	reservedHostPattern := `(?:(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?|(?:[a-z0-9_-]+\.)*(?:invalid|test|localhost))\.?`
	ignoredHostsPattern := `(?i)^[a-z][a-z0-9+.-]*://[^@\s]+@` + reservedHostPattern + `(?::[0-9]{1,5})?(?:,` + reservedHostPattern + `(?::[0-9]{1,5})?)*(?:[/?\s'"\x60#<>{}\[\];)]|,?$)`

	// Capture the password as the reported secret while retaining the URI's
	// credential-bearing structure as named captures. Every supported scheme
	// still requires explicit userinfo, keeping ordinary URLs and emails out.
	r := config.Rule{
		RuleID:      "generic-credential-uri",
		Confidence:  "medium",
		Description: "Detected a password embedded in a service connection URI, which may expose direct access to the referenced service.",
		Regex:       regexp.MustCompile(`(?i)\b(?P<uri>(?P<scheme>https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|ldaps?|smtps?|ftps?|ssh)://(?P<username>[^:/@\s'"\x60]{0,128}):(?P<password>[^/@\s'"\x60]{1,256})@(?P<host>(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252}))(?::[0-9]{1,5})?(?:,(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252})(?::[0-9]{1,5})?)*(?:[/?][a-z0-9._~!$&(*+,;=:@%/?-]*)?)(?:[\s'"\x60#<>{}\[\],;)]|\\[nr]|$)`),
		SecretGroup: 4,
		Keywords: []string{
			"http://",
			"https://",
			"postgres://",
			"postgresql://",
			"mysql://",
			"mariadb://",
			"mongodb://",
			"mongodb+srv://",
			"redis://",
			"rediss://",
			"amqp://",
			"amqps://",
			"ldap://",
			"ldaps://",
			"smtp://",
			"smtps://",
			"ftp://",
			"ftps://",
			"ssh://",
		},
		// Prefer this structural URI match over the generic username/password
		// rules while leaving provider-specific rules at the default 100 ahead.
		Specificity: 30,
		Filter: `let isExampleValue = filter.matchesAny(finding["secret"], [
  ` + "`(?i)^(?:(?:(?:an?|my)(?:[ _.-]|%(?:20|2d|5f))*)?example(?:(?:[ _.-]|%(?:20|2d|5f))*(?:password|passwd|pwd))?|(?:password|passwd|pwd)(?:[ _.-]|%(?:20|2d|5f))*example)(?:(?:[ _.-]|%(?:20|2d|5f))*[0-9]{1,4})?[!?.]*$`" + `
]);
let isInstructionalPlaceholder = filter.matchesAny(finding["secret"], [
  ` + "`(?i)^(?:[a-z0-9]+[_.-])?(?:your[_.-]?(?:password|passwd|pwd)|(?:password|passwd|pwd)[_.-]goes[_.-]?here|replace[_.-]?me|insert[_.-].*[_.-]here|placeholder)$`" + `
]);
let isSyntheticExampleURI = filter.matchesAny(finding["match"], [
  ` + "`(?i)^[a-z][a-z0-9+.-]*://(?:foo|user(?:name)?|example(?:[_.-]?user)?):(?:bar|pass(?:word)?|passwd|pwd|example(?:[_.-]?(?:password|passwd|pwd))?)@(?:(?:example|test)\\.(?:com|org|net)|example\\.invalid)(?::[0-9]{1,5})?(?:[/\\s'\"\\x60#]|$)`" + `
]);
let isSyntheticCredentialTuple = filter.matchesAny(finding["match"], [
  ` + "`(?i)^[a-z][a-z0-9+.-]*://(?:foo|test|user(?:name)?|example(?:[_.-]?user)?)[0-9]{0,4}:(?:bar|test|pass(?:word)?|passwd|pwd|token|secret)[0-9]{0,4}[!?.]?@`" + `
]);
let isTestOrDocumentationSource = filter.matchesAny(attributes["path"], [
  ` + "`(?i)(?:^|[/\\\\])(?:__tests__|tests?|testdata|specs?|fixtures?|mocks?|examples?|samples?|demos?|tutorials?|templates?|qa|e2e|documentation|docs?(?:[-_][a-z0-9-]+)?)(?:[/\\\\]|$)`" + `,
  ` + "`(?i)(?:^|[/\\\\])readme(?:\\.[^/\\\\]+)?$`" + `,
  ` + "`(?i)(?:^|[/\\\\])[^/\\\\]*(?:[_.-](?:test|spec)|(?:test|spec)[_.-])[^/\\\\]*\\.[^/\\\\]+$`" + `,
  ` + "`(?i)\\.(?:example|sample|template)(?:\\.[^/\\\\]+)?$`" + `,
  ` + "`(?i)\\.(?:md|mdx|rst|adoc|asciidoc)$`" + `
]);
let hasIgnoredHost = filter.matchesAny(finding["match"], [
  ` + "`" + ignoredHostsPattern + "`" + `
]);
let level = (
  isExampleValue
  || isSyntheticCredentialTuple
  || isTestOrDocumentationSource
) ? "low" : "medium";
let _ = filter.setConfidence(level);

// Discard mechanically non-literal credentials. Weak and default passwords
// remain reportable because the URI establishes their credential role.
isInstructionalPlaceholder
|| isSyntheticExampleURI
|| hasIgnoredHost
|| filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
  ` + "`(?i)^x{4,}$`" + `,
  ` + "`^•+$`" + `,
  ` + "`(?i)^\\[?(?:redacted|masked|filtered)\\]?$`" + `,
  ` + "`^\\$\\{.*}$`" + `,
  ` + "`^\\$\\([^\\r\\n]+\\)$`" + `,
  ` + "`^#\\{[^}\\r\\n]+}$`" + `,
  ` + "`^\\{\\{[ \\t]*.+[ \\t]*}}$`" + `,
  ` + "`^%\\{[^}]+}$`" + `,
  ` + "`^\\$[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`(?i)^\\$env:[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`^%[A-Za-z_][A-Za-z0-9_]*%$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^\\[[A-Za-z_][A-Za-z0-9_.-]*]$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`(?:\\$\\{|#\\{|\\{\\{|%\\{)`" + `
])`,
	}

	tps := []string{
		`DATABASE_URL="postgresql://alice:hunter2@db.internal/app"`,
		`SERVICE_URL="https://alice:s3cr3t@service.internal/api"`,
		`PROXY_URL=http://api-user:p%40ssword@proxy.internal:8080/v1`,
		`REDIS_URL=redis://:s3cr3t@cache.internal:6379/0`,
		`AMQP_URL='amqps://service:p%40ssword@rabbitmq.internal/vhost'`,
		`LDAP_URL=ldaps://directory-user:correct-horse@ldap.internal:636/dc=example,dc=com`,
		`SSH_URL=ssh://root:changeme@192.0.2.10:22/`,
		`MONGO_URL=mongodb://reader:q9V7nB2K4xL8@mongo1.internal:27017,mongo2.internal:27017/app`,
		`DATABASE_URL=POSTGRES://alice:example_password@db.internal/app`,
		`DATABASE_URL=postgres://alice:example%5Fpassword@db.internal/app`,
		`SSH_URL=ssh://foo:bar@gitlab.internal/repository`,
		`DATABASE_URL=postgresql://alice:hunter2@example.com,db.internal/app`,
		`SERVICE_URL=https://username:password@gitlab.company.com/api`,
	}
	fps := []string{
		`DATABASE_URL=postgres://alice@db.internal/app`,
		`DATABASE_URL=postgres://alice:@db.internal/app`,
		`DATABASE_URL=postgres://alice:${DB_PASSWORD}@db.internal/app`,
		`DATABASE_URL=postgres://alice:$DB_PASSWORD@db.internal/app`,
		`DATABASE_URL=postgres://{{ db_user }}:{{ db_password }}@db.internal/app`,
		`DATABASE_URL=postgres://<username>:<password>@db.internal/app`,
		`SSH_URL=ssh://foo:bar@example.com`,
		`FTP_URL=ftp://foo:bar@test.com/repository`,
		`REDIS_URL=redis://:redis-password-goes-here@gitlab-redis/`,
		`DATABASE_URL=postgres://user:password@example.org/app`,
		`SERVICE_URL=https://alice:s3cr3t@api.example.com/v1`,
		`DATABASE_URL=postgres://alice:hunter2@db.example.net/app`,
		`REDIS_URL=redis://:s3cr3t@cache.example/0`,
		`SSH_URL=ssh://alice:hunter2@host.invalid/repository`,
		`SERVICE_URL=https://alice:s3cr3t@service.test/v1`,
		`SERVICE_URL=http://user:pass:word@old_configurator.example.com)`,
		`SERVICE_URL=https://alice:s3cr3t@localhost/v1`,
		`REDIS_URL=redis://:s3cr3t@cache.localhost:6379/0`,
		`SERVICE_URL=https://alice:s3cr3t@example.com./v1`,
		`SERVICE_URL=https://alice:s3cr3t@example.com?mode=test`,
		`REDIS_URL=redis://:s3cr3t@cache.localhost.:6379/0`,
		`DATABASE_URL=postgresql://alice:hunter2@example.com,db.example.net/app`,
		`SERVICE_URL=http://username:password@example.com,https://test:test@example.org:9200`,
		`DATABASE_URL=postgres://alice:replace_me@db.internal/app`,
		`alice:hunter2@example.com`,
	}
	return utils.Validate(r, tps, fps)
}
