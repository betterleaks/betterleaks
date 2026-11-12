package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// STS GetCallerIdentity returns identity without establishing any permission
// grants. Analysis reuses that response and performs no additional requests.
// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
const awsAnalyzeExpr = `let input = validation.analysis;
let arn = input["arn"] ?? "";
{
  "reason": "AWS STS does not report credential permissions",
  "identity": {
    "id": input["userid"] ?? "",
    "username": matchesAny(arn, ["^arn:[^:]+:iam::[0-9]{12}:user/"]) ? last(split(arn, "/")) : "",
    "account": {"id": input["account"] ?? ""}
  },
  "metadata": arn != "" ? {"arn": arn} : {}
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "aws-access-token",
	Confidence:  "high",
	Description: "Identified an AWS access key ID paired with a secret access key, which together can provide full access to AWS services.",
	Regex:       `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`,
	Keywords: []string{
		// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
		"a3t",  // todo: might not be a valid AWS token
		"akia", // Access key
		"asia", // Temporary (AWS STS) access key
		"abia", // AWS STS service bearer token
		"acca", // Context-specific credential
	},
	Components: []config.Component{
		{
			RuleID:   "aws-secret-access-key",
			Optional: true,
			Within:   "5L",
		},
	},
	ValidateExpr: `let r = aws.validate(finding["secret"], (components["aws-secret-access-key"]?.secret ?? "")); r.status == 200 ? {
  "result": "valid",
  "analysis": {"arn": r.arn ?? "", "account": r.account ?? "", "userid": r.userid ?? ""}
} : r.status == 403 && r.error_code == "ExpiredToken" ? {
    "result": "revoked",
    "metadata": {"error_code": r.error_code, "error_message": r.error_message}
  } : r.status == 403 ? {
    "result": "invalid",
    "metadata": {"error_code": r.error_code, "error_message": r.error_message}
  } : validate.unknown(r)
`,
	AnalyzeExpr: awsAnalyzeExpr,
	FilterExpr:  "entropy(finding[\"secret\"]) <= 3.0\n|| matchesAny(finding[\"secret\"], [`.+EXAMPLE$`])",
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `AWSToken = "AKIALALEMEL33243OLIB"`, "AKIALALEMEL33243OLIB"),
		rulebuilder.Match("AWS assignment 2", `AWSToken = "AKIA3JBV3ATGC6AJ4LSU"`, "AKIA3JBV3ATGC6AJ4LSU"),
		rulebuilder.Match("AWS assignment 3", `AWSToken = "ASIA3JBV3ATGC6AJ4LSU"`, "ASIA3JBV3ATGC6AJ4LSU"),
		rulebuilder.Match("AWS assignment 4", `AWSToken = "ABIA3JBV3ATGC6AJ4LSU"`, "ABIA3JBV3ATGC6AJ4LSU"),
		rulebuilder.Match("AWS assignment 5", `AWSToken = "ACCA3JBV3ATGC6AJ4LSU"`, "ACCA3JBV3ATGC6AJ4LSU"),
		rulebuilder.NoMatch("Low entropy", "key = AKIAXXXXXXXXXXXXXXXX"),
		rulebuilder.NoMatch("Placeholder", "aws_access_key: AKIAIOSFODNN7EXAMPLE"),
		rulebuilder.NoMatch("Lowercase", `msgstr "Näytä asiakirjamallikansio."`),
		rulebuilder.NoMatch("wrong length", "TODAYINASIAASACKOFRICEFELLOVER"),
		rulebuilder.NoMatch("false positive 1", "CTTCATAGGGTTCACGCTGTGTAAT-ACG--CCTGAGGC-CACA-AGGGGACTTCAGCAACCGTCGGG-GATTC-ATTGCCA-A--TGGAAGCAATC-TA-TGGGTTA-TCGCGGAGTCCGCAAAGACGGCCAGTATG-AAGCAGATTTCGCAC-CAATGTGACTGCATTTCGTG-ATCGGGGTAAGTA-TC-GCCGATTC-GC--CCGTCCA-AGT-CGAAG-TA--GGCAATATAAAGCTGC-CATTGCCGAAGCTATCTCGCTA-TACTTGAT-AATCGGCGG-TAG-CACAG-GTCGCAGTATCG-AC-T--AGG-CCTCTCAAAAGTT-GGGTCCCGGCCTCTGGGAAAAACACCTCT-A-AGCGTCAATCAGCTCGGTTTCGCATATTA-TGATATCCCCCGTTGACCAATTGA--TAGTACCCGAGCTTACCGTCGG-ATTCTGGAGTCTT-ATGAGGTTACCGACGA-CGCAGTACCATAAGT-GCGCAATTTGACTGTTCCCGTCGAGTAACCA-AGCTTTGCTCA-CCGGGATGCGCGCCGATGTGACCAGGGGGCGCATGTTACATTGAC-A-GCTGGATCATGTTATGAC-GTGGGTC-ATGCTAAAAGCCTAAAGGACGGT-GCATTAGTAT-TACCGGGACCTCATATCAATGCGCTCGCTAGTTCCTCTTCTCTTGATAACGTATATGCGTCAGGCGCCCGTCCGCCTCCAATACGTG-ACAACGTC-AGTACTGAGCCTC--AA-ACATCGTCTTGTTCG-CC-TACAAAGGATCGGTAGAAAACTCAATATTCGGGTATAAGGTCGTAGGAAGTGTGTCGCCCAGGGCCG-CTAGA-AGCGCACACAAGCG-CTCCTGTCAAGGAGTTG-GTGAAAA-ATGAAC--GACT-ATTGCGTCAC--CTACCTCT-AAGTTTTT-GACAATTTCATGGACGAATTGA-AGCGTCCACAAGCATCTGCCGTAGATATGCGGTAGGTTTTTACATATG-TCACTGCAGAGTCACGGACA-CACATCGCTGTCAAAATGCTCGTACCTAGT-GT-TTGCGATCCCCC-GCGGCATTA-TCTTTTGAACCCTCGTCCCTGTGG-CTCTGATGATTGAG-GTCTGTA-TTCCCTCGTTGTGGGGGGATTGGACCTT-TGTATAGGTTCTTTAACCG-ATGGGGGGCCG--ATCGA-A-TA-TGCTCCTGTTTGCCCCGAACCTT-ACCTCGG-TCCAGACA-CTAAGAAAAACCCC-C-ACTGTAAGGTGCTGAGCCTTTGGATAGCC-CGCGAATGAT-CC-TAGTTGACAA-CTGAACGCGCTCGAACA-TGCCC-GCCCTCTGA--CTGCTGTCTG-GCACCTTTAGACACGCGTCGAC-CATATATT-AGCGCTGTCTGTGG-AGGT-TGTGTCTTGTTGCTCA-CT-CATTATCTGT-AACTGGCTCC-CTC-CCAT-TGGCGTCTTTACACCAACCGCTAGGTTACAGTGCA-TCTAGCGCCTATTATCAGGGCGT-TTGCAGCGGCGCGGTGGCTATGT-GTTAGACATATC-CTTACACTGTATGCTAG-AGCAAGCCAC-TCTGAATGGGTTGC-CGATGAATGA-TCTTGATC-GAGCTCGCA-AC---TACATGGAGTCCGAAGTGAACCTACGGATGATCGTATTCCAACACGAGGATC-TATACGTATAGG-A-GGCG-TAATCCACAATTTAGTAACTCTTGACGC---GGATGAAAAT-GTCGTTACACCTTCCAGAGGCTCGG-GTATATATATGACCT--TGTGATTGAGGACGATCTAGAATAA-CT-GT-G-CT-AAAGTACAGTAGTTTCTATGT-GGTAGGTGGAGAATACAGAGTAG-ATGATTC-GTGGGCCACA-C--T-ACTTTCAT-TAGAGCAGAGA-C-GTGAGTGAGTTTTACACTAGCCAGATGGACCG-GTGA-AGTCTAACAGCCACCGCTT-GTGAGGTCGTTTCCCAGTC-ACCCTACTACAGGCAAAAACTCAGTGT-CC-GTGA-GTGCGTTAGTGATATTCCCTAACGGTTAGGTAACT-CATGAATTCA-AT-TAAGCGTGTCC-CGGT-CACGCCCCCATGGGGGCCTTCTTGGGAGG--AGCATCTTAT--AT-GCTCACGTGGTT-GATAGG-A-T-AATACACTTTTAGTCAGTCCATCAATAAC-AAAGGAAC---CAGGTGGTCGCAGATA-TCCCGCTGATATAGCACTGTGTAAACTCAGGTGATA-CTAAGC--GCTCTAAT-ACG-CTTAATGGCAATGCCCAGTTC--ACGACTAGCTTATGAGGCCCAGCTATGGACTGCGGC-GGCATGTCGGC-GATGGTTGCCCTCGCCCTAAATTATGTACGA-T-ACCGCCT-CTTGTTCT-CCGCCCATAGGGT-C--AGCAGGCGATAGACTCCCAGAAATTTCCTCGTCGT-CCGAATAAGACTAACACGACTA-TT-CCTCTAC-GT-G-AA-CTTATCA-CAAATG-GCT-TACC-TAGGTGGTGGCAGATCACTTTCCGGTG-TATTACGAATTGACGCATACCGAC-A-CGC-GCTTGTTGGATAATCGACTCTAACCTCCTCTCTGGCACATGT-GCTGGATTACCTC-TATTTT-TCTCGCTTAG--GGAACG-T-CCTCTGTCGCGTGAG-GTACGTTTCACGGGAG-CGGCTTGTTCATGCCACGTCCATTATCGA-AGTG-C-GTAAGG-A-GAGCCCTA--GACTCTACACGGAAA-TC-AAC-GTAGAAGGCTC-A-CT"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "aws-secret-access-key",
	Confidence:  "medium",
	Description: "Identified an AWS secret access key, used as a component of the aws-access-token composite rule.",
	Regex:       rulebuilder.Assignment([]string{"secret", "access", "key", "token"}, `[A-Za-z0-9/+=]{40}`),
	Keywords:    []string{"secret", "access", "key", "token"},
	// SkipReport suppresses standalone secret-key findings; the key is
	// always surfaced as a required component of the aws-access-token finding.
	SkipReport: true,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("aws_secret_key assignment", `aws_secret_keyToken = "XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbc"`, "XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbc"),
		rulebuilder.MatchComponent("secret_access_key assignment", `secret_access_keyToken = "XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbc"`, "XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbc"),
	},
})

// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-how.html
// https://medium.com/@adan.alvarez/api-keys-for-bedrock-a-brief-security-overview-2133ed9a2b3f
var _ = rulebuilder.Add(config.Rule{
	ID:          "aws-amazon-bedrock-api-key-long-lived",
	Confidence:  "high",
	Description: "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
	Regex:       rulebuilder.Token(`ABSK[A-Za-z0-9+/]{109,269}={0,2}`),
	Keywords: []string{
		"absk", // Amazon Bedrock API Key (long-lived)
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("Valid API key example", "ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM=", "ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM="),
		rulebuilder.Match("true positive 1", `bedrock_api_token = "ABSKQmVkcm9ja0FQSUtleS15fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2ad="`, "ABSKQmVkcm9ja0FQSUtleS15fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2ad="),
		rulebuilder.Match("true positive 2", `bedrock_api_token = "ABSKQmVkcm9ja0FQSUtleS15fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2adus61vq0dnd3i2a93m65mv90fpqrp820foz4g8nk2zk47gstvluy2vrm66r6ofguizc8mdr3na9g3wrucvy5q5oosz6wk9cn1ekni7osfbcac7bdc31575xagykswyxt4gbuoofx5o8"`, "ABSKQmVkcm9ja0FQSUtleS15fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2adus61vq0dnd3i2a93m65mv90fpqrp820foz4g8nk2zk47gstvluy2vrm66r6ofguizc8mdr3na9g3wrucvy5q5oosz6wk9cn1ekni7osfbcac7bdc31575xagykswyxt4gbuoofx5o8"),
		rulebuilder.NoMatch("Too short key (missing characters)", "ABSKQmVkcm9ja0FQSUtleS1EXAMPLE"),
		rulebuilder.NoMatch("Too long", "ABSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE="),
		rulebuilder.NoMatch("Wrong prefix", "AXSKQmVkcm9ja0FQSUtleS1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXM="),
	},
})

// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-how.html
// https://github.com/aws/aws-bedrock-token-generator-js/blob/86277e1489354192c64ffc8f995601daacc1f715/src/token.ts#L21
var _ = rulebuilder.Add(config.Rule{
	ID:          "aws-amazon-bedrock-api-key-short-lived",
	Confidence:  "high",
	Description: "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
	Regex:       `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`,
	Keywords: []string{
		"bedrock-api-key-", // Amazon Bedrock API Key (short lived)
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `AmazonBedrockAPIKeyShortLivedToken = "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"`, "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"),
		rulebuilder.NoMatch("Too short key (missing characters)", "bedrock-api-key-"),
		rulebuilder.NoMatch("Wrong prefix", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29x"),
	},
})
