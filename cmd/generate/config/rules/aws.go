package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "aws-access-token",
		Description: "Identified an AWS access key ID paired with a secret access key, which together can provide full access to AWS services.",
		Regex:       regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
		Entropy:     3,
		Keywords: []string{
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
			"A3T",  // todo: might not be a valid AWS token
			"AKIA", // Access key
			"ASIA", // Temporary (AWS STS) access key
			"ABIA", // AWS STS service bearer token
			"ACCA", // Context-specific credential
		},
		RequiredRules: []*config.Required{
			{
				RuleID:      "aws-secret-access-key",
				WithinLines: utils.IntPtr(5),
			},
		},
		ValidateCEL: `cel.bind(r,
  aws.validate(secret, captures["aws-secret-access-key"]),
  r.status == 200 ? {
    "result": "valid",
    "arn": r.arn,
    "account": r.account,
    "userid": r.userid
  } : r.status == 403 && r.error_code == "ExpiredToken" ? {
    "result": "revoked",
    "error_code": r.error_code,
    "error_message": r.error_message
  } : r.status == 403 ? {
    "result": "invalid",
    "error_code": r.error_code,
    "error_message": r.error_message
  } : unknown(r)
)
`,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`.+EXAMPLE$`),
				},
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("AWS", "AKIALALEMEL33243OLIB") // gitleaks:allow
	// current AWS tokens cannot contain [0,1,8,9], so their entropy is slightly lower than expected.
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "AKIA"+secrets.NewSecretWithEntropy("[A-Z2-7]{16}", 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ASIA"+secrets.NewSecretWithEntropy("[A-Z2-7]{16}", 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ABIA"+secrets.NewSecretWithEntropy("[A-Z2-7]{16}", 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ACCA"+secrets.NewSecretWithEntropy("[A-Z2-7]{16}", 3))...)
	fps := []string{
		`key = AKIAXXXXXXXXXXXXXXXX`,           // Low entropy
		`aws_access_key: AKIAIOSFODNN7EXAMPLE`, // Placeholder
		`msgstr "Näytä asiakirjamallikansio."`, // Lowercase
		`TODAYINASIAASACKOFRICEFELLOVER`,       // wrong length
		`CTTCATAGGGTTCACGCTGTGTAAT-ACG--CCTGAGGC-CACA-AGGGGACTTCAGCAACCGTCGGG-GATTC-ATTGCCA-A--TGGAAGCAATC-TA-TGGGTTA-TCGCGGAGTCCGCAAAGACGGCCAGTATG-AAGCAGATTTCGCAC-CAATGTGACTGCATTTCGTG-ATCGGGGTAAGTA-TC-GCCGATTC-GC--CCGTCCA-AGT-CGAAG-TA--GGCAATATAAAGCTGC-CATTGCCGAAGCTATCTCGCTA-TACTTGAT-AATCGGCGG-TAG-CACAG-GTCGCAGTATCG-AC-T--AGG-CCTCTCAAAAGTT-GGGTCCCGGCCTCTGGGAAAAACACCTCT-A-AGCGTCAATCAGCTCGGTTTCGCATATTA-TGATATCCCCCGTTGACCAATTGA--TAGTACCCGAGCTTACCGTCGG-ATTCTGGAGTCTT-ATGAGGTTACCGACGA-CGCAGTACCATAAGT-GCGCAATTTGACTGTTCCCGTCGAGTAACCA-AGCTTTGCTCA-CCGGGATGCGCGCCGATGTGACCAGGGGGCGCATGTTACATTGAC-A-GCTGGATCATGTTATGAC-GTGGGTC-ATGCTAAAAGCCTAAAGGACGGT-GCATTAGTAT-TACCGGGACCTCATATCAATGCGCTCGCTAGTTCCTCTTCTCTTGATAACGTATATGCGTCAGGCGCCCGTCCGCCTCCAATACGTG-ACAACGTC-AGTACTGAGCCTC--AA-ACATCGTCTTGTTCG-CC-TACAAAGGATCGGTAGAAAACTCAATATTCGGGTATAAGGTCGTAGGAAGTGTGTCGCCCAGGGCCG-CTAGA-AGCGCACACAAGCG-CTCCTGTCAAGGAGTTG-GTGAAAA-ATGAAC--GACT-ATTGCGTCAC--CTACCTCT-AAGTTTTT-GACAATTTCATGGACGAATTGA-AGCGTCCACAAGCATCTGCCGTAGATATGCGGTAGGTTTTTACATATG-TCACTGCAGAGTCACGGACA-CACATCGCTGTCAAAATGCTCGTACCTAGT-GT-TTGCGATCCCCC-GCGGCATTA-TCTTTTGAACCCTCGTCCCTGTGG-CTCTGATGATTGAG-GTCTGTA-TTCCCTCGTTGTGGGGGGATTGGACCTT-TGTATAGGTTCTTTAACCG-ATGGGGGGCCG--ATCGA-A-TA-TGCTCCTGTTTGCCCCGAACCTT-ACCTCGG-TCCAGACA-CTAAGAAAAACCCC-C-ACTGTAAGGTGCTGAGCCTTTGGATAGCC-CGCGAATGAT-CC-TAGTTGACAA-CTGAACGCGCTCGAACA-TGCCC-GCCCTCTGA--CTGCTGTCTG-GCACCTTTAGACACGCGTCGAC-CATATATT-AGCGCTGTCTGTGG-AGGT-TGTGTCTTGTTGCTCA-CT-CATTATCTGT-AACTGGCTCC-CTC-CCAT-TGGCGTCTTTACACCAACCGCTAGGTTACAGTGCA-TCTAGCGCCTATTATCAGGGCGT-TTGCAGCGGCGCGGTGGCTATGT-GTTAGACATATC-CTTACACTGTATGCTAG-AGCAAGCCAC-TCTGAATGGGTTGC-CGATGAATGA-TCTTGATC-GAGCTCGCA-AC---TACATGGAGTCCGAAGTGAACCTACGGATGATCGTATTCCAACACGAGGATC-TATACGTATAGG-A-GGCG-TAATCCACAATTTAGTAACTCTTGACGC---GGATGAAAAT-GTCGTTACACCTTCCAGAGGCTCGG-GTATATATATGACCT--TGTGATTGAGGACGATCTAGAATAA-CT-GT-G-CT-AAAGTACAGTAGTTTCTATGT-GGTAGGTGGAGAATACAGAGTAG-ATGATTC-GTGGGCCACA-C--T-ACTTTCAT-TAGAGCAGAGA-C-GTGAGTGAGTTTTACACTAGCCAGATGGACCG-GTGA-AGTCTAACAGCCACCGCTT-GTGAGGTCGTTTCCCAGTC-ACCCTACTACAGGCAAAAACTCAGTGT-CC-GTGA-GTGCGTTAGTGATATTCCCTAACGGTTAGGTAACT-CATGAATTCA-AT-TAAGCGTGTCC-CGGT-CACGCCCCCATGGGGGCCTTCTTGGGAGG--AGCATCTTAT--AT-GCTCACGTGGTT-GATAGG-A-T-AATACACTTTTAGTCAGTCCATCAATAAC-AAAGGAAC---CAGGTGGTCGCAGATA-TCCCGCTGATATAGCACTGTGTAAACTCAGGTGATA-CTAAGC--GCTCTAAT-ACG-CTTAATGGCAATGCCCAGTTC--ACGACTAGCTTATGAGGCCCAGCTATGGACTGCGGC-GGCATGTCGGC-GATGGTTGCCCTCGCCCTAAATTATGTACGA-T-ACCGCCT-CTTGTTCT-CCGCCCATAGGGT-C--AGCAGGCGATAGACTCCCAGAAATTTCCTCGTCGT-CCGAATAAGACTAACACGACTA-TT-CCTCTAC-GT-G-AA-CTTATCA-CAAATG-GCT-TACC-TAGGTGGTGGCAGATCACTTTCCGGTG-TATTACGAATTGACGCATACCGAC-A-CGC-GCTTGTTGGATAATCGACTCTAACCTCCTCTCTGGCACATGT-GCTGGATTACCTC-TATTTT-TCTCGCTTAG--GGAACG-T-CCTCTGTCGCGTGAG-GTACGTTTCACGGGAG-CGGCTTGTTCATGCCACGTCCATTATCGA-AGTG-C-GTAAGG-A-GAGCCCTA--GACTCTACACGGAAA-TC-AAC-GTAGAAGGCTC-A-CT`,
	}
	return utils.Validate(r, tps, fps)
}

func AWSSecretAccessKey() *config.Rule {
	r := config.Rule{
		RuleID:      "aws-secret-access-key",
		Description: "Identified an AWS secret access key, used as a component of the aws-access-token composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"aws_secret_access_key", "aws_secret_key", "secret_access_key"},
			`[A-Za-z0-9/+=]{40}`,
			false,
		),
		Entropy:  4,
		Keywords: []string{"aws_secret_access_key", "aws_secret_key", "secret_access_key"},
		// SkipReport suppresses standalone secret-key findings; the key is
		// always surfaced as a required component of the aws-access-token finding.
		SkipReport: true,
	}

	tps := utils.GenerateSampleSecrets("aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	tps = append(tps, utils.GenerateSampleSecrets("aws_secret_key", secrets.NewSecretWithEntropy(`[A-Za-z0-9/+=]{40}`, 4))...)
	tps = append(tps, utils.GenerateSampleSecrets("secret_access_key", secrets.NewSecretWithEntropy(`[A-Za-z0-9/+=]{40}`, 4))...)
	return utils.Validate(r, tps, nil)
}

func AmazonBedrockAPIKeyLongLived() *config.Rule {
	// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-how.html
	// https://medium.com/@adan.alvarez/api-keys-for-bedrock-a-brief-security-overview-2133ed9a2b3f
	r := config.Rule{
		RuleID:      "aws-amazon-bedrock-api-key-long-lived",
		Description: "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
		Regex:       utils.GenerateUniqueTokenRegex(`ABSK[A-Za-z0-9+/]{109,269}={0,2}`, false),
		Entropy:     3,
		Keywords: []string{
			"ABSK", // Amazon Bedrock API Key (long-lived)
		},
	}

	// validate
	tps := []string{
		// Valid API key example
		"ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM=",
		// Generate additional random test keys
		utils.GenerateSampleSecret("bedrock", "ABSKQmVkcm9ja0FQSUtleS1"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("108"), 3)+"="),
		utils.GenerateSampleSecret("bedrock", "ABSKQmVkcm9ja0FQSUtleS1"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("246"), 3)),
	}

	fps := []string{
		// Too short key (missing characters)
		"ABSKQmVkcm9ja0FQSUtleS1EXAMPLE",
		// Too long
		"ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE=",
		// Wrong prefix
		"AXSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM=",
	}

	return utils.Validate(r, tps, fps)
}

func AmazonBedrockAPIKeyShortLived() *config.Rule {
	// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-how.html
	// https://github.com/aws/aws-bedrock-token-generator-js/blob/86277e1489354192c64ffc8f995601daacc1f715/src/token.ts#L21
	r := config.Rule{
		RuleID:      "aws-amazon-bedrock-api-key-short-lived",
		Description: "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
		Regex:       regexp.MustCompile(`bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`),
		Entropy:     3,
		Keywords: []string{
			"bedrock-api-key-", // Amazon Bedrock API Key (short lived)
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("AmazonBedrockAPIKeyShortLived", `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`)

	fps := []string{
		// Too short key (missing characters)
		"bedrock-api-key-",
		// Wrong prefix
		"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29x",
	}

	return utils.Validate(r, tps, fps)
}
