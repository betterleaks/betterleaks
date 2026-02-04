package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func ArtifactoryApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-api-key",
		Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`),
		Entropy:     4.5,
		Keywords:    []string{"AKCp"},
	}

	// validate
	tps := []string{
		"artifactoryApiKey := \"AKCp" + secrets.NewSecret(utils2.AlphaNumeric("69")) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"AkCp" + secrets.NewSecret(utils2.AlphaNumeric("69")) + "\"",
		"wrongLength := \"AkCp" + secrets.NewSecret(utils2.AlphaNumeric("59")) + "\"",
		"partOfAlongUnrelatedBlob gYnkgAkCp" + secrets.NewSecret(utils2.AlphaNumeric("69")) + "VyZSB2",
	}

	return utils2.Validate(r, tps, fps)
}

func ArtifactoryReferenceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-reference-token",
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`),
		Entropy:     4.5,
		Keywords:    []string{"cmVmd"},
	}

	// validate
	tps := []string{
		"artifactoryRefToken := \"cmVmd" + secrets.NewSecret(utils2.AlphaNumeric("59")) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"cmVMd" + secrets.NewSecret(utils2.AlphaNumeric("59")) + "\"",
		"wrongLength := \"cmVmd" + secrets.NewSecret(utils2.AlphaNumeric("49")) + "\"",
		"partOfAlongUnrelatedBlob gYnkgcmVmd" + secrets.NewSecret(utils2.AlphaNumeric("59")) + "VyZSB2",
	}

	return utils2.Validate(r, tps, fps)
}
