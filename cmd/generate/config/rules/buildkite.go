package rules

import (
	"strings"

	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func BuildkiteUserAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "buildkite-user-access-token",
		Description: "Detected a Buildkite user access token, which may expose pipelines, builds, and organization data.",
		Regex:       regexp.MustCompile(`\b(bkua_(?:[a-z0-9]{40}|[a-z0-9]{53}))\b`),
		Keywords:    []string{"bkua_"},
		ValidateExpr: utils.BearerGetValidationExpr(
			"https://api.buildkite.com/v2/access-token",
			`(r.body contains "\"scopes\"")`,
		),
		Filter: utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`BUILDKITE_TOKEN=bkua_hqlh73m51jtho0jh12wcf2758c8fcdbv05z023ly`,
			`BUILDKITE_TOKEN=bkua_q9xk4pt8cw1zl6gh3sd5fj0ab7nm2qv9xk4pt8cw1zl6gh3sd5fj0`,
		},
		[]string{
			`BUILDKITE_TOKEN=bkua_short`,
			`BUILDKITE_TOKEN=bkua_hqlh73m51jtho0jh12wcf2758c8fcdbv05z023ly_extra`,
		},
	)
}

func BuildkiteServiceToken() *config.Rule {
	r := config.Rule{
		RuleID:      "buildkite-service-token",
		Description: "Detected a Buildkite agent, package, or portal token, which may expose CI/CD workloads or packages.",
		Regex: regexp.MustCompile(`\b(` +
			`bkaa_[A-Za-z0-9_-]{75}|` +
			`bkaj_[A-Za-z0-9_-]{333}|` +
			`bkar_[A-Za-z0-9_-]{73}|` +
			`bkct_[A-Za-z0-9_-]{73}|` +
			`bkpt_[A-Za-z0-9_-]{199}|` +
			`bkpat_[A-Za-z0-9_-]{54}|` +
			`bkps_[A-Za-z0-9_-]{64}` +
			`)(?:$|[^A-Za-z0-9_-])`),
		Keywords: []string{"bkaa_", "bkaj_", "bkar_", "bkct_", "bkpt_", "bkpat_", "bkps_"},
		Filter:   utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`BUILDKITE_AGENT_TOKEN=bkaa_` + buildkiteTestToken(75),
			`BUILDKITE_JOB_TOKEN=bkaj_` + buildkiteTestToken(333),
			`BUILDKITE_REGISTRATION_TOKEN=bkar_` + buildkiteTestToken(73),
			`BUILDKITE_CLUSTER_TOKEN=bkct_` + buildkiteTestToken(73),
			`BUILDKITE_PACKAGE_TOKEN=bkpt_` + buildkiteTestToken(199),
			`BUILDKITE_PORTAL_TOKEN=bkpat_` + buildkiteTestToken(54),
			`BUILDKITE_PORTAL_SECRET=bkps_` + buildkiteTestToken(64),
			`BUILDKITE_AGENT_TOKEN=bkaa_` + buildkiteTestToken(74) + `-]`,
		},
		[]string{
			`BUILDKITE_AGENT_TOKEN=bkaa_` + buildkiteTestToken(74),
			`BUILDKITE_AGENT_TOKEN=bkaa_` + buildkiteTestToken(74) + `-extra`,
		},
	)
}

func buildkiteTestToken(length int) string {
	const alphabet = "aB3dE6gH9jK2mN5qR8tV1xY4zC7fG0iL"
	return strings.Repeat(alphabet, length/len(alphabet)+1)[:length]
}
