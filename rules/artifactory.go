package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "artifactory-api-key",
	Confidence:  "high",
	Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
	Regex:       `\bAKCp[A-Za-z0-9]{68,70}\b`,
	Keywords:    []string{"AKCp"},
	Components: []config.Component{
		{RuleID: "artifactory-jfrog-url"},
	},
	ValidateExpr: `let r = http.get("https://" + (components["artifactory-jfrog-url"]?.secret ?? "") + "/artifactory/api/repositories", {
    "X-JFrog-Art-Api": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "artifactoryApiKey := \"AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn\"\nARTIFACTORY_URL=https://mycompany.jfrog.io",
			Expect: []config.ExpectedFinding{
				{Secret: "AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn", ComponentSets: []map[string]string{{"artifactory-jfrog-url": "mycompany.jfrog.io"}}},
			},
		},
		NoMatch("false positive 1", "lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
		NoMatch("false positive 2", `wrongStart := "AkCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn"`),
		NoMatch("false positive 3", `wrongLength := "AkCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7"`),
		NoMatch("false positive 4", "partOfAlongUnrelatedBlob gYnkgAkCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqnVyZSB2"),
	},
})

var _ = Add(config.Rule{
	ID:          "artifactory-reference-token",
	Confidence:  "high",
	Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
	Regex:       `\bcmVmd[A-Za-z0-9]{59}\b`,
	Keywords:    []string{"cmVmd"},
	Components: []config.Component{
		{RuleID: "artifactory-jfrog-url"},
	},
	ValidateExpr: `let r = http.get("https://" + (components["artifactory-jfrog-url"]?.secret ?? "") + "/artifactory/api/repositories", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "artifactoryRefToken := \"cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7\"\nARTIFACTORY_URL=https://mycompany.jfrog.io",
			Expect: []config.ExpectedFinding{
				{Secret: "cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7", ComponentSets: []map[string]string{{"artifactory-jfrog-url": "mycompany.jfrog.io"}}},
			},
		},
		NoMatch("false positive 1", "lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
		NoMatch("false positive 2", `wrongStart := "cmVMd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7"`),
		NoMatch("false positive 3", `wrongLength := "cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysj"`),
		NoMatch("false positive 4", "partOfAlongUnrelatedBlob gYnkgcmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7VyZSB2"),
	},
})

var _ = Add(config.Rule{
	ID:          "artifactory-jfrog-url",
	Confidence:  "high",
	Description: "Detected a JFrog Artifactory host, used as a component of Artifactory token validation.",
	Regex:       `(?i)(?:^|[^a-z0-9-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.jfrog\.io)(?:$|[^a-z0-9-])`,
	Keywords:    []string{"jfrog.io"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "ARTIFACTORY_URL=https://mycompany.jfrog.io",
			Expect: []config.ExpectedFinding{
				{Secret: "mycompany.jfrog.io"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "JFROG_URL=my-company-name.jfrog.io",
			Expect: []config.ExpectedFinding{
				{Secret: "my-company-name.jfrog.io"},
			},
		},
		{
			Name:  "true positive 3",
			Mode:  "match",
			Input: "host: a.jfrog.io",
			Expect: []config.ExpectedFinding{
				{Secret: "a.jfrog.io"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "JFROG_URL=-bad.jfrog.io",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "JFROG_URL=bad-.jfrog.io",
			Expect: []config.ExpectedFinding{},
		},
	},
})
