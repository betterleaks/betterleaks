package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
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
		"artifactoryApiKey := \"AKCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"AkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "\"",
		"wrongLength := \"AkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
		"partOfAlongUnrelatedBlob gYnkgAkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
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
		"artifactoryRefToken := \"cmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"cmVMd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
		"wrongLength := \"cmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("49"), 4.5) + "\"",
		"partOfAlongUnrelatedBlob gYnkgcmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
}
