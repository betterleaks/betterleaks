package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericCredentialURI() *config.Rule {
	// Capture the password as the reported secret while retaining the URI's
	// credential-bearing structure as named captures. The deliberately narrow
	// scheme list keeps ordinary HTTP URLs and email addresses out of this rule.
	r := config.Rule{
		RuleID:      "generic-credential-uri",
		Confidence:  "medium",
		Description: "Detected a password embedded in a service connection URI, which may expose direct access to the referenced service.",
		Regex:       regexp.MustCompile(`(?i)\b(?P<uri>(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|ldaps?|smtps?|ftps?|ssh)://(?P<username>[^:/@\s'"\x60]{0,128}):(?P<password>[^/@\s'"\x60]{1,256})@(?P<host>(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252}))(?::[0-9]{1,5})?(?:,(?:\[[0-9a-f:.%]+\]|[a-z0-9][a-z0-9._-]{0,252})(?::[0-9]{1,5})?)*(?:[/?][a-z0-9._~!$&(*+,;=:@%/?-]*)?)(?:[\s'"\x60#<>{}\[\],;)]|\\[nr]|$)`),
		SecretGroup: 4,
		Keywords: []string{
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
  ` + "`(?i)^(?:(?:(?:an?|my)(?:[ _.-]|%(?:20|2d|5f))*)?example(?:(?:[ _.-]|%(?:20|2d|5f))*(?:password|passwd|pwd))?|(?:password|passwd|pwd)(?:[ _.-]|%(?:20|2d|5f))*example)(?:(?:[ _.-]|%(?:20|2d|5f))*[0-9]{1,4})?[!?.]*$`" + `,
  ` + "`(?i)^(?:your[_-]?(?:password|passwd|pwd)|replace[_-]?me|password[_-]?goes[_-]?here|insert[_-].*[_-]here|placeholder)$`" + `
]);
let level = isExampleValue ? "low" : "medium";
let _ = filter.setConfidence(level);

// Discard mechanically non-literal credentials. Weak and default passwords
// remain reportable because the URI establishes their credential role.
filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
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
  ` + "`(?:\\$\\{|#\\{|\\{\\{|%\\{)`" + `
])`,
	}

	tps := []string{
		`DATABASE_URL="postgresql://alice:hunter2@db.example.com/app"`,
		`REDIS_URL=redis://:s3cr3t@cache.internal:6379/0`,
		`AMQP_URL='amqps://service:p%40ssword@rabbitmq.example.com/vhost'`,
		`LDAP_URL=ldaps://directory-user:correct-horse@ldap.internal:636/dc=example,dc=com`,
		`SSH_URL=ssh://root:changeme@192.0.2.10:22/`,
		`MONGO_URL=mongodb://reader:q9V7nB2K4xL8@mongo1.internal:27017,mongo2.internal:27017/app`,
		`DATABASE_URL=POSTGRES://alice:example_password@localhost/app`,
		`DATABASE_URL=postgres://alice:example%5Fpassword@localhost/app`,
	}
	fps := []string{
		`DATABASE_URL=postgres://alice@db.example.com/app`,
		`DATABASE_URL=postgres://alice:@db.example.com/app`,
		`DATABASE_URL=postgres://alice:${DB_PASSWORD}@db.example.com/app`,
		`DATABASE_URL=postgres://alice:$DB_PASSWORD@db.example.com/app`,
		`DATABASE_URL=postgres://{{ db_user }}:{{ db_password }}@db.example.com/app`,
		`DATABASE_URL=postgres://<username>:<password>@db.example.com/app`,
		`https://alice:hunter2@example.com/api`,
		`alice:hunter2@example.com`,
	}
	return utils.Validate(r, tps, fps)
}
