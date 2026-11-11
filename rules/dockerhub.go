package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "dockerhub-personal-access-token",
	Confidence:  "high",
	Description: "Detected a Docker Hub personal access token, which may expose Docker Hub account access.",
	Regex:       Token(`dckr_pat_[A-Za-z0-9_-]{27}`),
	Keywords:    []string{"dckr_pat_"},
	FilterExpr:  MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "docker login -u gemesa -p dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y", "dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y"),
		Match("true positive 2", "docker login -u gemesa -p dckr_pat_tkzBYxjNNC3R_Yg6jd_O-G8FbrJ", "dckr_pat_tkzBYxjNNC3R_Yg6jd_O-G8FbrJ"),
	},
})

var _ = Add(config.Rule{
	ID:          "dockerhub-organization-access-token",
	Confidence:  "high",
	Description: "Detected a Docker Hub organization access token, which may expose organization repositories.",
	Regex:       Token(`dckr_oat_[A-Za-z0-9_-]{32}`),
	Keywords:    []string{"dckr_oat_"},
	FilterExpr:  MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "docker login -u docker-test -p dckr_oat_7bA9zRt5-JqX3vP0l_MnY8sK2wE-dF6h", "dckr_oat_7bA9zRt5-JqX3vP0l_MnY8sK2wE-dF6h"),
	},
})
