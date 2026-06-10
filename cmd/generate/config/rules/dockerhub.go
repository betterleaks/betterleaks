package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DockerHubPersonalAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "dockerhub-personal-access-token",
		Description: "Detected a Docker Hub personal access token, which may expose Docker Hub account access.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_pat_[A-Za-z0-9_-]{27}`, false),
		Keywords:    []string{"dckr_pat_"},
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`docker login -u gemesa -p dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y`,
		`docker login -u gemesa -p dckr_pat_tkzBYxjNNC3R_Yg6jd_O-G8FbrJ`,
	}
	return utils.Validate(r, tps, nil)
}

func DockerHubOrganizationAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "dockerhub-organization-access-token",
		Description: "Detected a Docker Hub organization access token, which may expose organization repositories.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_oat_[A-Za-z0-9_-]{32}`, false),
		Keywords:    []string{"dckr_oat_"},
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`docker login -u docker-test -p dckr_oat_7bA9zRt5-JqX3vP0l_MnY8sK2wE-dF6h`,
	}
	return utils.Validate(r, tps, nil)
}
