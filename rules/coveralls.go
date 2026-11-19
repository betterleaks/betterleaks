package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "coveralls-personal-api-token",
	Confidence:  "medium",
	Description: "Detected a Coveralls personal API token, which may expose repository coverage data.",
	Regex:       rulebuilder.Assignment([]string{"coveralls"}, `(?i)[A-Za-z0-9-]{37}`),
	Keywords:    []string{"coveralls"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "coveralls_SECRETTOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t"),
		rulebuilder.Match("true positive 2", "coveralls-SECRET-KEY=m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f", "m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f"),
		rulebuilder.Match("true positive 3", "coveralls_PRIVATEKEY=1234567890bcdefghijklmnpqrstuvwxyza12", "1234567890bcdefghijklmnpqrstuvwxyza12"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "coveralls-repo-token",
	Confidence:  "medium",
	Description: "Detected a Coveralls repository token, which may allow uploading coverage reports or viewing private repository coverage data.",
	Regex:       rulebuilder.Assignment([]string{"coveralls"}, `[A-Za-z0-9]{33}`),
	Keywords:    []string{"coveralls"},
	ValidateExpr: `let r = http.post("https://coveralls.io/api/v1/jobs", {"Content-Type": "multipart/form-data; boundary=betterleaks", "User-Agent": "Go-http-client/1.1"}, "--betterleaks\r\nContent-Disposition: form-data; name=\"json_file\"; filename=\"json_file.json\"\r\nContent-Type: application/json\r\n\r\n{\"repo_token\": \"" + finding["secret"] + "\", \"source_files\": \"invalid_type_string\"}\r\n--betterleaks--\r\n");
(r.status in [500] && r.body contains "Build processing error.") ? {"result": "valid"} :
(r.status in [422] && r.body contains "Couldn't find a repository matching this job.") ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `coveralls = "f70xzAUCYPFLXC6oqAtjsFQFqNFciWcVy"`, `f70xzAUCYPFLXC6oqAtjsFQFqNFciWcVy`),
		rulebuilder.NoMatch("near miss 1", `coveralls = "141jQMttDmyt5Vvq4Hlu5jBDMvvHRNT4"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "coveralls-repo-token-coveralls-yml",
	Confidence:  "medium",
	Description: "Detected a Coveralls repository token, which may allow uploading coverage reports or viewing private repository coverage data.",
	Regex:       `\b` + rulebuilder.Assignment([]string{"repo_token"}, `[A-Za-z0-9]{33}`),
	Path:        `(?i)(?:^|/)\.coveralls\.yml$`,
	Keywords:    []string{"repo_token"},
	ValidateExpr: `let r = http.post("https://coveralls.io/api/v1/jobs", {"Content-Type": "multipart/form-data; boundary=betterleaks", "User-Agent": "Go-http-client/1.1"}, "--betterleaks\r\nContent-Disposition: form-data; name=\"json_file\"; filename=\"json_file.json\"\r\nContent-Type: application/json\r\n\r\n{\"repo_token\": \"" + finding["secret"] + "\", \"source_files\": \"invalid_type_string\"}\r\n--betterleaks--\r\n");
(r.status in [500] && r.body contains "Build processing error.") ? {"result": "valid"} :
(r.status in [422] && r.body contains "Couldn't find a repository matching this job.") ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		{
			Name:       "shape 1 in .coveralls.yml",
			Input:      `repo_token = "f70xzAUCYPFLXC6oqAtjsFQFqNFciWcVy"`,
			Attributes: map[string]string{"path": ".coveralls.yml"},
			Expect:     []config.ExpectedFinding{{Secret: "f70xzAUCYPFLXC6oqAtjsFQFqNFciWcVy"}},
		},
		{
			Name:       "shape 1 in package.json",
			Input:      `repo_token = "f70xzAUCYPFLXC6oqAtjsFQFqNFciWcVy"`,
			Attributes: map[string]string{"path": "package.json"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
