package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(GenericCredentialURI())

func GenericCredentialURI() config.Rule {
	documentationHostPattern := `(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?\.?`
	localOrReservedHostPattern := `(?:(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?|(?:[a-z0-9_-]+\.)*(?:invalid|test|localhost))\.?`
	onlyHostListPattern := func(hostPattern string) string {
		return `(?i)^[a-z][a-z0-9+.-]*://[^@\s]+@` + hostPattern + `(?::[0-9]{1,5})?(?:,` + hostPattern + `(?::[0-9]{1,5})?)*(?:[/?\s'"\x60#<>{}\[\];)]|,?$)`
	}
	ignoredHostsPattern := onlyHostListPattern(documentationHostPattern)
	lowConfidenceHostsPattern := onlyHostListPattern(localOrReservedHostPattern)
	// Capture the password as the reported secret while retaining the URI's
	// credential-bearing structure as named captures. Every supported scheme
	// still requires explicit userinfo, keeping ordinary URLs and emails out.
	r := config.Rule{
		ID:          "generic-credential-uri",
		Confidence:  "medium",
		Description: "Detected a password embedded in a service connection URI, which may expose direct access to the referenced service.",
		Regex:       `(?i)\b(?P<uri>(?P<scheme>https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|ldaps?|smtps?|ftps?|ssh)://(?P<username>[^:/@\s'"\x60]{0,128}):(?P<password>[^/@\s'"\x60]{1,256})@(?P<host>(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252}))(?::[0-9]{1,5})?(?:,(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252})(?::[0-9]{1,5})?)*(?:[/?][a-z0-9._~!$&(*+,;=:@%/?-]*)?)(?:[\s'"\x60#<>{}\[\],;)]|\\[nr]|$)`,
		ValueGroup:  4,
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
		Specificity: -70,
		FilterExpr: `let isExampleValue = matchesAny(finding["secret"], [
  ` + "`(?i)^(?:(?:(?:an?|my)(?:[ _.-]|%(?:20|2d|5f))*)?example(?:(?:[ _.-]|%(?:20|2d|5f))*(?:password|passwd|pwd))?|(?:password|passwd|pwd)(?:[ _.-]|%(?:20|2d|5f))*example)(?:(?:[ _.-]|%(?:20|2d|5f))*[0-9]{1,4})?[!?.]*$`" + `
]);
let isInstructionalPlaceholder = matchesAny(finding["secret"], [
  ` + "`(?i)^(?:[a-z0-9]+[_.-])?(?:your[_.-]?(?:password|passwd|pwd)|(?:password|passwd|pwd)[_.-]goes[_.-]?here|replace[_.-]?me|insert[_.-].*[_.-]here|placeholder)$`" + `
]);
let isSyntheticExampleURI = matchesAny(finding["match"], [
  ` + "`(?i)^[a-z][a-z0-9+.-]*://(?:foo|user(?:name)?|example(?:[_.-]?user)?):(?:bar|pass(?:word)?|passwd|pwd|example(?:[_.-]?(?:password|passwd|pwd))?)@(?:(?:example|test)\\.(?:com|org|net)|example\\.invalid)(?::[0-9]{1,5})?(?:[/\\s'\"\\x60#]|$)`" + `
]);
let isSyntheticCredentialTuple = matchesAny(finding["match"], [
  ` + "`(?i)^[a-z][a-z0-9+.-]*://(?:foo|test|user(?:name)?|example(?:[_.-]?user)?)[0-9]{0,4}:(?:bar|test|pass(?:word)?|passwd|pwd|token|secret)[0-9]{0,4}[!?.]?@`" + `
]);
let isTestOrDocumentationSource = matchesAny(attributes["path"], [
  ` + "`(?i)(?:^|[/\\\\])(?:__tests__|tests?|testdata|specs?|fixtures?|mocks?|examples?|samples?|demos?|tutorials?|templates?|qa|e2e|documentation|docs?(?:[-_][a-z0-9-]+)?)(?:[/\\\\]|$)`" + `,
  ` + "`(?i)(?:^|[/\\\\])readme(?:\\.[^/\\\\]+)?$`" + `,
  ` + "`(?i)(?:^|[/\\\\])[^/\\\\]*(?:[_.-](?:test|spec)|(?:test|spec)[_.-])[^/\\\\]*\\.[^/\\\\]+$`" + `,
  ` + "`(?i)\\.(?:example|sample|template)(?:\\.[^/\\\\]+)?$`" + `,
  ` + "`(?i)\\.(?:md|mdx|rst|adoc|asciidoc)$`" + `
]);
let hasIgnoredHost = matchesAny(finding["match"], [
  ` + "`" + ignoredHostsPattern + "`" + `
]);
let hasLowConfidenceHost = matchesAny(finding["match"], [
  ` + "`" + lowConfidenceHostsPattern + "`" + `
]);
let level = (
  isExampleValue
  || isSyntheticCredentialTuple
  || isTestOrDocumentationSource
  || hasLowConfidenceHost
) ? "low" : "medium";
let _ = setConfidence(level);

// Discard mechanically non-literal credentials. Weak and default passwords
// remain reportable because the URI establishes their credential role.
isInstructionalPlaceholder
|| isSyntheticExampleURI
|| hasIgnoredHost
|| matchesAny(finding["secret"], [
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
	r.Tests = []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: `DATABASE_URL="postgresql://alice:hunter2@db.internal/app"`,
			Expect: []config.ExpectedFinding{
				{Secret: "hunter2", Captures: map[string]string{"host": "db.internal", "password": "hunter2", "scheme": "postgresql", "uri": "postgresql://alice:hunter2@db.internal/app", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 2",
			Input: `SERVICE_URL="https://alice:s3cr3t@service.internal/api"`,
			Expect: []config.ExpectedFinding{
				{Secret: "s3cr3t", Captures: map[string]string{"host": "service.internal", "password": "s3cr3t", "scheme": "https", "uri": "https://alice:s3cr3t@service.internal/api", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "PROXY_URL=http://api-user:p%40ssword@proxy.internal:8080/v1",
			Expect: []config.ExpectedFinding{
				{Secret: "p%40ssword", Captures: map[string]string{"host": "proxy.internal", "password": "p%40ssword", "scheme": "http", "uri": "http://api-user:p%40ssword@proxy.internal:8080/v1", "username": "api-user"}},
			},
		},
		{
			Name:  "true positive 4",
			Input: "REDIS_URL=redis://:s3cr3t@cache.internal:6379/0",
			Expect: []config.ExpectedFinding{
				{Secret: "s3cr3t", Captures: map[string]string{"host": "cache.internal", "password": "s3cr3t", "scheme": "redis", "uri": "redis://:s3cr3t@cache.internal:6379/0"}},
			},
		},
		{
			Name:  "true positive 5",
			Input: "AMQP_URL='amqps://service:p%40ssword@rabbitmq.internal/vhost'",
			Expect: []config.ExpectedFinding{
				{Secret: "p%40ssword", Captures: map[string]string{"host": "rabbitmq.internal", "password": "p%40ssword", "scheme": "amqps", "uri": "amqps://service:p%40ssword@rabbitmq.internal/vhost", "username": "service"}},
			},
		},
		{
			Name:  "true positive 6",
			Input: "LDAP_URL=ldaps://directory-user:correct-horse@ldap.internal:636/dc=example,dc=com",
			Expect: []config.ExpectedFinding{
				{Secret: "correct-horse", Captures: map[string]string{"host": "ldap.internal", "password": "correct-horse", "scheme": "ldaps", "uri": "ldaps://directory-user:correct-horse@ldap.internal:636/dc=example,dc=com", "username": "directory-user"}},
			},
		},
		{
			Name:  "true positive 7",
			Input: "SSH_URL=ssh://root:changeme@192.0.2.10:22/",
			Expect: []config.ExpectedFinding{
				{Secret: "changeme", Captures: map[string]string{"host": "192.0.2.10", "password": "changeme", "scheme": "ssh", "uri": "ssh://root:changeme@192.0.2.10:22/", "username": "root"}},
			},
		},
		{
			Name:  "true positive 8",
			Input: "MONGO_URL=mongodb://reader:q9V7nB2K4xL8@mongo1.internal:27017,mongo2.internal:27017/app",
			Expect: []config.ExpectedFinding{
				{Secret: "q9V7nB2K4xL8", Captures: map[string]string{"host": "mongo1.internal", "password": "q9V7nB2K4xL8", "scheme": "mongodb", "uri": "mongodb://reader:q9V7nB2K4xL8@mongo1.internal:27017,mongo2.internal:27017/app", "username": "reader"}},
			},
		},
		{
			Name:  "true positive 9",
			Input: "DATABASE_URL=POSTGRES://alice:example_password@db.internal/app",
			Expect: []config.ExpectedFinding{
				{Secret: "example_password", Captures: map[string]string{"host": "db.internal", "password": "example_password", "scheme": "POSTGRES", "uri": "POSTGRES://alice:example_password@db.internal/app", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 10",
			Input: "DATABASE_URL=postgres://alice:example%5Fpassword@db.internal/app",
			Expect: []config.ExpectedFinding{
				{Secret: "example%5Fpassword", Captures: map[string]string{"host": "db.internal", "password": "example%5Fpassword", "scheme": "postgres", "uri": "postgres://alice:example%5Fpassword@db.internal/app", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 11",
			Input: "SSH_URL=ssh://foo:bar@gitlab.internal/repository",
			Expect: []config.ExpectedFinding{
				{Secret: "bar", Captures: map[string]string{"host": "gitlab.internal", "password": "bar", "scheme": "ssh", "uri": "ssh://foo:bar@gitlab.internal/repository", "username": "foo"}},
			},
		},
		{
			Name:  "true positive 12",
			Input: "DATABASE_URL=postgresql://alice:hunter2@example.com,db.internal/app",
			Expect: []config.ExpectedFinding{
				{Secret: "hunter2", Captures: map[string]string{"host": "example.com", "password": "hunter2", "scheme": "postgresql", "uri": "postgresql://alice:hunter2@example.com,db.internal/app", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 13",
			Input: "SERVICE_URL=https://username:password@gitlab.company.com/api",
			Expect: []config.ExpectedFinding{
				{Secret: "password", Captures: map[string]string{"host": "gitlab.company.com", "password": "password", "scheme": "https", "uri": "https://username:password@gitlab.company.com/api", "username": "username"}},
			},
		},
		{
			Name:  "true positive 14",
			Input: "SSH_URL=ssh://alice:hunter2@host.invalid/repository",
			Expect: []config.ExpectedFinding{
				{Secret: "hunter2", Captures: map[string]string{"host": "host.invalid", "password": "hunter2", "scheme": "ssh", "uri": "ssh://alice:hunter2@host.invalid/repository", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 15",
			Input: "SERVICE_URL=https://alice:s3cr3t@service.test/v1",
			Expect: []config.ExpectedFinding{
				{Secret: "s3cr3t", Captures: map[string]string{"host": "service.test", "password": "s3cr3t", "scheme": "https", "uri": "https://alice:s3cr3t@service.test/v1", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 16",
			Input: "SERVICE_URL=https://alice:s3cr3t@localhost/v1",
			Expect: []config.ExpectedFinding{
				{Secret: "s3cr3t", Captures: map[string]string{"host": "localhost", "password": "s3cr3t", "scheme": "https", "uri": "https://alice:s3cr3t@localhost/v1", "username": "alice"}},
			},
		},
		{
			Name:  "true positive 17",
			Input: "REDIS_URL=redis://:s3cr3t@cache.localhost:6379/0",
			Expect: []config.ExpectedFinding{
				{Secret: "s3cr3t", Captures: map[string]string{"host": "cache.localhost", "password": "s3cr3t", "scheme": "redis", "uri": "redis://:s3cr3t@cache.localhost:6379/0"}},
			},
		},
		NoMatch("false positive 1", "DATABASE_URL=postgres://alice@db.internal/app"),
		NoMatch("false positive 2", "DATABASE_URL=postgres://alice:@db.internal/app"),
		NoMatch("false positive 3", "DATABASE_URL=postgres://alice:${DB_PASSWORD}@db.internal/app"),
		NoMatch("false positive 4", "DATABASE_URL=postgres://alice:$DB_PASSWORD@db.internal/app"),
		NoMatch("false positive 5", "DATABASE_URL=postgres://{{ db_user }}:{{ db_password }}@db.internal/app"),
		NoMatch("false positive 6", "DATABASE_URL=postgres://<username>:<password>@db.internal/app"),
		NoMatch("false positive 7", "SSH_URL=ssh://foo:bar@example.com"),
		NoMatch("false positive 8", "FTP_URL=ftp://foo:bar@test.com/repository"),
		NoMatch("false positive 9", "REDIS_URL=redis://:redis-password-goes-here@gitlab-redis/"),
		NoMatch("false positive 10", "DATABASE_URL=postgres://user:password@example.org/app"),
		NoMatch("false positive 11", "SERVICE_URL=https://alice:s3cr3t@api.example.com/v1"),
		NoMatch("false positive 12", "DATABASE_URL=postgres://alice:hunter2@db.example.net/app"),
		NoMatch("false positive 13", "REDIS_URL=redis://:s3cr3t@cache.example/0"),
		NoMatch("false positive 14", "SERVICE_URL=http://user:pass:word@old_configurator.example.com)"),
		NoMatch("false positive 15", "SERVICE_URL=https://alice:s3cr3t@example.com./v1"),
		NoMatch("false positive 16", "SERVICE_URL=https://alice:s3cr3t@example.com?mode=test"),
		NoMatch("false positive 17", "DATABASE_URL=postgresql://alice:hunter2@example.com,db.example.net/app"),
		NoMatch("false positive 18", "SERVICE_URL=http://username:password@example.com,https://test:test@example.org:9200"),
		NoMatch("false positive 19", "DATABASE_URL=postgres://alice:replace_me@db.internal/app"),
		NoMatch("false positive 20", "alice:hunter2@example.com"),
	}
	return r
}
