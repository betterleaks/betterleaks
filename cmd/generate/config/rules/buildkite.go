package rules

import (
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://buildkite.com/docs/apis/rest-api/access-token
const buildkiteValidateExpr = `let r = http.get("https://api.buildkite.com/v2/access-token", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
}); r.status == 200 && r.json?.scopes != nil ? {
  "result": "valid",
  "analysis": {
    "token_id": r.json?.uuid ?? "",
    "token_name": r.json?.description ?? "",
    "scopes": r.json?.scopes ?? [],
    "name": r.json?.user?.name ?? "",
    "email": r.json?.user?.email ?? "",
    "created_at": r.json?.created_at ?? "",
    "expires_at": r.json?.expires_at ?? ""
  }
} : r.status in [401, 403] ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`

// Match documented REST scopes; GraphQL access does not describe the user's
// effective permissions. Reading secret details does not expose secret values.
// https://buildkite.com/docs/apis/managing-api-tokens
const buildkiteAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let can_read = matchesAny(scopes, [
  "^read_(?:pipelines|builds|build_logs|job_env|artifacts|agents|clusters|pipeline_templates|rules|organizations|organization_invitations|organization_settings|organization_repository_connections|notification_services|teams|user|audit_events|secrets_details|suites|test_plan|registries|packages|portals)$"
]);
let can_write = matchesAny(scopes, [
  "^write_(?:pipelines|builds|build_logs|artifacts|agents|clusters|pipeline_templates|rules|organizations|organization_invitations|organization_settings|notification_services|teams|secrets|suites|test_plan|registries|packages|portals)$",
  "^delete_(?:registries|packages)$"
]);
{
  "reason": "graphql" in scopes ? "Buildkite GraphQL permissions were not expanded" :
    len(scopes) == 0 ? "Buildkite did not return token scopes" :
    !can_read && !can_write ? "Buildkite returned no recognized REST permission grants" : "",
  "identity": {
    "name": input["name"] ?? "",
    "email": input["email"] ?? ""
  },
  "metadata": {
    "token_id": input["token_id"] ?? "",
    "token_name": input["token_name"] ?? "",
    "scopes": scopes,
    "created_at": input["created_at"] ?? "",
    "expires_at": input["expires_at"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": can_read,
    "write": can_write,
    "manage_users": intersects(scopes, ["write_organizations", "write_organization_invitations", "write_teams"])
  })
}`

func BuildkiteUserAccessToken() *config.Rule {
	r := config.Rule{
		ID:           "buildkite-user-access-token",
		Confidence:   "high",
		Description:  "Detected a Buildkite user access token, which may expose pipelines, builds, and organization data.",
		Regex:        `\b(bkua_(?:[a-z0-9]{40}|[a-z0-9]{53}))\b`,
		Keywords:     []string{"bkua_"},
		ValidateExpr: buildkiteValidateExpr,
		AnalyzeExpr:  buildkiteAnalyzeExpr,
		Filter:       utils.MinEntropy(3.5),
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
		ID:          "buildkite-service-token",
		Confidence:  "high",
		Description: "Detected a Buildkite agent, package, or portal token, which may expose CI/CD workloads or packages.",
		Regex: `\b(` +
			`bkaa_[A-Za-z0-9_-]{75}|` +
			`bkaj_[A-Za-z0-9_-]{333}|` +
			`bkar_[A-Za-z0-9_-]{73}|` +
			`bkct_[A-Za-z0-9_-]{73}|` +
			`bkpt_[A-Za-z0-9_-]{199}|` +
			`bkpat_[A-Za-z0-9_-]{54}|` +
			`bkps_[A-Za-z0-9_-]{64}` +
			`)(?:$|[^A-Za-z0-9_-])`,
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
