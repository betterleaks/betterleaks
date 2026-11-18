package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "nx-cloud-access-token",
	Confidence:  "high",
	Description: "Detected an Nx Cloud access token, which may allow access to remote computation caching and workspace task execution in Nx Cloud.",
	Regex:       rulebuilder.Assignment([]string{"nxcloud", "nx_cloud", "nx\\-cloud"}, `(?:[A-Za-z0-9+/=]{64}|[A-Za-z0-9+/=]{56})`),
	Keywords:    []string{"nxcloud", "nx_cloud", "nx-cloud"},
	ValidateExpr: `let r = http.get("https://cloud.nx.app/nx-cloud/data/v1/cipes?" + "limit=1", {"Authorization": "Bearer " + finding["secret"], "User-Agent": "Go-http-client/1.1"});
(r.status in [200] && (r.json?.items ?? "") != "") ? {"result": "valid"} :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `nxcloud = "R9KtvlWAySzfZH5QfeMh7uaINCJUzCVnNURe7oN15Leecr1OA7nyrM6FkmJ0M0CY"`, `R9KtvlWAySzfZH5QfeMh7uaINCJUzCVnNURe7oN15Leecr1OA7nyrM6FkmJ0M0CY`),
		rulebuilder.Match("shape 2", `nxcloud = "nd8u7pOsD9jxrTIchKTMaWYb/cVWqZn=keTiVWjPYQOWBaVXZuoQef8B"`, `nd8u7pOsD9jxrTIchKTMaWYb/cVWqZn=keTiVWjPYQOWBaVXZuoQef8B`),
		rulebuilder.NoMatch("near miss 1", `nxcloud = "OWExErUqIKUhGiV7Kh58FDHgYGj6GTZuAAF1IikoCNMkHTK5kORsJSZuv17weQ="`),
		rulebuilder.NoMatch("near miss 2", `nxcloud = "MTQ1XGHeFJKaCUMcFQ42CgQ8VYhsHQvoRSZeQCNuVIj0FaO4jVHgYW="`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "nx-cloud-access-token-nx-json",
	Confidence:  "high",
	Description: "Detected an Nx Cloud access token, which may allow access to remote computation caching and workspace task execution in Nx Cloud.",
	Regex:       `\b` + rulebuilder.Assignment([]string{"accesstoken"}, `(?:[A-Za-z0-9+/=]{64}|[A-Za-z0-9+/=]{56})`),
	Path:        `(?i)(?:^|/)nx\.json$`,
	Keywords:    []string{"accesstoken"},
	ValidateExpr: `let r = http.get("https://cloud.nx.app/nx-cloud/data/v1/cipes?" + "limit=1", {"Authorization": "Bearer " + finding["secret"], "User-Agent": "Go-http-client/1.1"});
(r.status in [200] && (r.json?.items ?? "") != "") ? {"result": "valid"} :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		{
			Name:       "shape 1 in nx.json",
			Input:      `accesstoken = "R9KtvlWAySzfZH5QfeMh7uaINCJUzCVnNURe7oN15Leecr1OA7nyrM6FkmJ0M0CY"`,
			Attributes: map[string]string{"path": "nx.json"},
			Expect:     []config.ExpectedFinding{{Secret: "R9KtvlWAySzfZH5QfeMh7uaINCJUzCVnNURe7oN15Leecr1OA7nyrM6FkmJ0M0CY"}},
		},
		{
			Name:       "shape 2 in nx.json",
			Input:      `accesstoken = "nd8u7pOsD9jxrTIchKTMaWYb/cVWqZn=keTiVWjPYQOWBaVXZuoQef8B"`,
			Attributes: map[string]string{"path": "nx.json"},
			Expect:     []config.ExpectedFinding{{Secret: "nd8u7pOsD9jxrTIchKTMaWYb/cVWqZn=keTiVWjPYQOWBaVXZuoQef8B"}},
		},
		{
			Name:       "shape 1 in package.json",
			Input:      `accesstoken = "R9KtvlWAySzfZH5QfeMh7uaINCJUzCVnNURe7oN15Leecr1OA7nyrM6FkmJ0M0CY"`,
			Attributes: map[string]string{"path": "package.json"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
