// Package generic defines the default rules that are not specific to a
// provider: generic API keys, passwords, and credential URIs.
package generic

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// One line break allows pretty-printed records while keeping the scanner's
// keyword search windows small. No structural punctuation may be skipped.
const jsonRecordSpace = `[ \t]*(?:\r?\n[ \t]*)?`
const jsonRecordValue = jsonRecordSpace + `"?value"?` + jsonRecordSpace + `:` + jsonRecordSpace

// Attributes must be quoted and single-line. Bound their count and separating
// newlines so opening tags cannot cross markup or expand keyword windows freely.
const xmlAttribute = `(?:[ \t]+|[ \t]*\r?\n[ \t]*)[\w.:-]{1,64}[ \t]*=[ \t]*(?:"[^"<\r\n]*"|'[^'<\r\n]*')`
const xmlOpeningTagEnd = `(?:` + xmlAttribute + `){0,5}` + jsonRecordSpace + `>`
const xmlClosingTag = `</[\w.:-]{1,64}` + jsonRecordSpace + `>`

// Only flat, single-line scalar fields may precede an explicit "value" field.
// Quoted strings consume their own escapes, commas, and braces.
const jsonScalar = `(?:"(?:\\[^\r\n]|[^"\\\r\n])*"|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)`
const jsonValueSiblings = `(?:"[\w.-]+"[ \t]*:[ \t]*` + jsonScalar + `[ \t]*,` + jsonRecordSpace + `){1,5}?`
const jsonValueObject = `\{` + jsonRecordSpace + jsonValueSiblings + `"value"` + jsonRecordSpace + `:`

// Follow up to two opening containers. Prefer an explicit "value" after up to
// five scalar siblings; otherwise retain the first-child behavior.
const structuredContainer = jsonRecordSpace + `(?:(?:\[` + jsonRecordSpace + `)?\{` + jsonRecordSpace + `"[\w.-]{1,64}"` + jsonRecordSpace + `:|<[\w.:-]{1,64}` + xmlOpeningTagEnd + `)`
const structuredValuePrefix = `(?:(?:` + structuredContainer + `)?` + jsonRecordSpace + `(?:\[` + jsonRecordSpace + `)?` + jsonValueObject + `|(?:` + structuredContainer + `){0,2})` + jsonRecordSpace

// Sibling metadata does not describe the secret. Keep parent and child names
// in filter context, but remove fields skipped on the way to "value".
const structuredMatchContext = `let siblingMetadata = containsAny(finding["match"], ["{"])
  ? findMatch(finding["match"], ` + "`(?i)" + jsonValueObject + "`" + `) : "";
let credentialMatch = siblingMetadata == "" ? finding["match"]
  : replace(finding["match"], siblingMetadata, "{\"value\":", 1);
`

// Match a named child field, including its opening container. Bare words in a
// literal must not be mistaken for metadata.
func structuredFieldPattern(names string) string {
	return `(?:(?:\[` + jsonRecordSpace + `)?\{` + jsonRecordSpace + `"(?:` + names + `)"` + jsonRecordSpace + `:|<(?:[\w.-]+:)?(?:` + names + `)` + xmlOpeningTagEnd + `)`
}

var _ = rulebuilder.Add(genericCredential())

func genericCredential() config.Rule {
	const identifiers = `access|auth|(?-i:[Aa]pi|API)|credential|creds|key|secret|token`
	const token = `[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}`
	// Recognize labels such as S3_API_KEY without consuming a long, unbroken
	// token assigned directly to "key" as a record label.
	recordLabel := jsonRecordSpace + `"(?:[a-z0-9]{0,16}[_.-]){0,4}(?:` + identifiers + `)[a-z0-9_.-]{0,20}"` + jsonRecordSpace + `(?:,` + jsonRecordValue + `|value[ \t]*=|>)`
	operator := `(?:(?:=>|:{1,3}=|\|\||\?=|[=:])(?:` + recordLabel + `)?|,(?:` + jsonRecordValue + `)?|['"]` + jsonRecordSpace + `(?:value[ \t]*=|>))`
	// Keep the identifier on one line. Whitespace may precede the operator,
	// but a comment must not absorb the next line's field or assignment.
	identifier := `(?:` + identifiers + `)[ \t'"\w.-]{0,20}[ \t'"]{0,20}` + jsonRecordSpace
	// Require the opening '<'. Rejecting closing tags in a filter is too late:
	// a discarded match could have already consumed the next element's secret.
	xmlIdentifier := `<[\w.:-]{0,64}(?:` + identifiers + `)[\w.:-]{0,20}` + xmlOpeningTagEnd
	r := config.Rule{
		ID:          "generic-api-key",
		Confidence:  "low",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex: `(?i)(?:` + identifier + operator + `|` + xmlIdentifier + `)` + structuredValuePrefix + `(?:<!\[CDATA\[)?` +
			`[\x60'"\s=]{0,5}(` + token + `)(?:\\?['"\x60]|[\s;]|` + xmlClosingTag + `|\]\]>|\\[nr]|$)`,
		Keywords: []string{
			"access",
			"api",
			"auth",
			"key",
			"credential",
			"creds",
			"secret",
			"token",
		},
		Specificity: -100,
		FilterExpr: `// Reject implausible values before preparing context and confidence.
entropy(finding["secret"]) <= 3.5
|| failsTokenEfficiency(finding["secret"])
|| (
` + structuredMatchContext + `
// Remove XML attributes from complete opening tags in the name-filter context.
// Preserve element names and literal text.
let nameContext = containsAny(credentialMatch, ["<"])
  ? join(map(split(credentialMatch, "<"), {
      let tag = findMatch(#, ` + "`^[\\w.:-]+" + xmlOpeningTagEnd + "`" + `);
      tag == "" ? # : replace(#, tag, findMatch(tag, ` + "`^[\\w.:-]+`" + `) + ">", 1)
    }), "<")
  : credentialMatch;

matchesAny(nameContext, [
  // Permit an indented operator on the next line, but do not bridge blank lines.
  ` + "`^[\\w.'\" \\t-]*\\r?\\n[ \\t'\"]*\\r?\\n`" + `,
  // Credential containers can hold public identifiers or public key material.
  ` + "`(?i)" + structuredFieldPattern(`client[_.-]?id|guid|X509Certificate|Modulus|Exponent`) + "`" + `
])
// Tie public-key version examples to the prose immediately before this match.
|| (containsAny(finding["match"], ["<"])
  && matchesAny(finding["match"], [` + "`(?i)^key(?: result)?\\.[ \\t]+For example:[ \\t]*<code>`" + `])
  && matchesAny(finding["fragment_raw"][
    max(finding["match_start_idx"] - 150, finding["match_line_start_idx"]):finding["match_start_idx"]
  ], [` + "`" + `(?i)\b(?:version|etag)\b[^<>"'\r\n=]{0,100}\bpublic[ \t]+$` + "`" + `]))
|| (
// Provider checks use a fixed window around the match, clamped to its line.
let providerMatchContext = finding["fragment_raw"][
  max(finding["match_start_idx"] - 150, finding["match_line_start_idx"]):
  min(finding["match_end_idx"] + 50, finding["match_line_end_idx"])
];

// Recreate the generic rule's former [\w.-]{0,50} preamble. Only the
// contiguous word, dot, and hyphen suffix immediately before the match counts.
let genericMatchPrefix = findMatch(
  finding["fragment_raw"][
    max(finding["match_start_idx"] - 50, finding["match_line_start_idx"]):
    finding["match_start_idx"]
  ],
  ` + "`[\\w.-]{0,50}$`" + `
);

// Keep credential-path names and confidence hints, excluding skipped metadata.
let genericMatchContext =
  genericMatchPrefix +
  nameContext;

let level = matchesAny(genericMatchContext, [
  ` + "`(?i)\\b[a-z0-9]+[_.-]+token\\b`" + `
]) ? "medium" : "low";
let _ = setConfidence(level);

// big ol expression to filter out FPs
` + genericAPIKeyFilter + `
)
)`,
	}
	r.Tests = []config.RuleTest{
		rulebuilder.Match("assignment", `genericToken = "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"`, "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"),
		rulebuilder.Match("generic assignment 2", `genericToken = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"`, "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
		rulebuilder.Match("true positive 1", "'access_token': 'eyJ0eXAioiJKV1slS3oASx=='", "eyJ0eXAioiJKV1slS3oASx=="),
		rulebuilder.Match("true positive 2", `some_api_token_123 = "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmnt"`, "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmnt"),
		rulebuilder.Match("true positive 3", `"user_auth": "am9obmRvZTpkMDY5NGIxYi1jMTcxLTQ4ODYt+TMyYS0wMmUwOWQ1/mIwNjc="`, "am9obmRvZTpkMDY5NGIxYi1jMTcxLTQ4ODYt+TMyYS0wMmUwOWQ1/mIwNjc="),
		rulebuilder.Match("true positive 4", `"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`, "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"),
		rulebuilder.Match("true positive 5", "creds = RFbD56TI2smTyVsGd5Xav0yu99ZAMP", "RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.Match("true positive 6", "private-key: KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7pF3KxefvfivPDCACDJjCC5xOa50opKtiOLPeKH9BjLZNf-.SPZOIpYzMtbhyBJcdXdX1GH", "KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7pF3KxefvfivPDCACDJjCC5xOa50opKtiOLPeKH9BjLZNf-.SPZOIpYzMtbhyBJcdXdX1GH"),
		rulebuilder.Match("true positive 7", `"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`, "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde"),
		rulebuilder.Match("true positive 8", "mySecretString=RFbD56TI2smTyVsGd5Xav0yu99ZAMP", "RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.Match("true positive 9", "todo_secret_do_not_commit = RFbD56TI2smTyVsGd5Xav0yu99ZAMP", "RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.Match("true positive 10", ` utils.GetEnvOrDefault("api_token", "dafa7817-e246-48f3-91a7-e87653d587b8")`, "dafa7817-e246-48f3-91a7-e87653d587b8"),
		rulebuilder.Match("random key containing a word", `api_key = "Xk2q9TfZrB7wLhookpN4cVy8sJ3mQe6RdG1aUoHn"`, "Xk2q9TfZrB7wLhookpN4cVy8sJ3mQe6RdG1aUoHn"),
		rulebuilder.Match("random key containing a word 2", `api_key = "p8RvN3qLdataZx7KcW2mYt9BfJ4hGs6EuA1oTnVi"`, "p8RvN3qLdataZx7KcW2mYt9BfJ4hGs6EuA1oTnVi"),
		rulebuilder.Match("key starting with C.", `api_key = "C.A1B2C3D4E5F6G7H8I9J0K1"`, "C.A1B2C3D4E5F6G7H8I9J0K1"),
		rulebuilder.NoMatch("Access", `"accessor":"rA1wk0Y45YCufyfq",`),
		rulebuilder.NoMatch("false positive 1", "report_access_id: e8e4df51-2054-49b0-ab1c-516ac95c691d"),
		rulebuilder.NoMatch("false positive 2", `accessibilityYesOptionId = "0736f5ef-7e88-499a-80cc-90c85d2a5180"`),
		rulebuilder.NoMatch("false positive 3", "_RandomAccessIterator>\n_LIBCPP_CONSTEXPR_AFTER_CXX11 "),
		rulebuilder.NoMatch("API", `this.ultraPictureBox1.Name = "ultraPictureBox1";`),
		rulebuilder.NoMatch("false positive 4", "rapidstring:marm64-uwp=fail"),
		rulebuilder.NoMatch("false positive 5", "event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'"),
		rulebuilder.NoMatch("false positive 6", "COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT"),
		rulebuilder.NoMatch("false positive 7", "MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1"),
		rulebuilder.NoMatch("false positive 8", "[DEBUG]\t\torg.slf4j.slf4j-api:jar:1.7.8.:compile (version managed from default)"),
		rulebuilder.NoMatch("false positive 9", "[DEBUG]\t\torg.neo4j.neo4j-graphdb-api:jar:3.5.12:test"),
		rulebuilder.NoMatch("false positive 10", "apiUrl=apigee.corpint.com"),
		rulebuilder.NoMatch("false positive 11", `X-API-Name": "NRG0-Hermes-INTERNAL-API",`),
		rulebuilder.NoMatch("Auth", `author = "james.fake@ymail.com",`),
		rulebuilder.NoMatch("false positive 12", "X-MS-Exchange-Organization-AuthSource: sm02915.int.contoso.com"),
		rulebuilder.NoMatch("false positive 13", "Authentication-Results: 5h.ca.iphmx.com"),
		rulebuilder.NoMatch("Credentials", "withCredentials([usernamePassword(credentialsId: '29f63271-dc2f-4734-8221-5b31b5169bac', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {"),
		rulebuilder.NoMatch("false positive 14", "credentialsId: 'ff083f76-7804-4ef1-80e4-fe975bb9141b'"),
		rulebuilder.NoMatch("false positive 15", "jobCredentialsId: 'f4aeb6bc-2a25-458a-8111-9be9e502c0e7'"),
		rulebuilder.NoMatch("false positive 16", `  "credentialId": "B9mTcFSck2LzJO2S3ols63",`),
		rulebuilder.NoMatch("false positive 17", "environment {\n\tCREDENTIALS_ID = \"K8S_CRED\"\n}"),
		rulebuilder.NoMatch("false positive 18", "dev.credentials.url=dev-lb1.api.f4ke.com:5215"),
		rulebuilder.NoMatch("Key", `keyword: "Befaehigung_P2"`),
		rulebuilder.NoMatch("false positive 19", `public_key = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`),
		rulebuilder.NoMatch("false positive 20", "pub const X509_pubkey_st = struct_X509_pubkey_st;"),
		rulebuilder.NoMatch("false positive 21", "|| pIdxKey->default_rc==0"),
		rulebuilder.NoMatch("false positive 22", "monkeys-audio:mx64-uwp=fail"),
		rulebuilder.NoMatch("false positive 23", "primaryKey=KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7"),
		rulebuilder.NoMatch("false positive 24", "foreignKey=KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7"),
		rulebuilder.NoMatch("false positive 25", "key_down_event=KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7"),
		rulebuilder.NoMatch("false positive 26", "issuerKeyHash=KfnhAi5kP4Npo9Vkl3bZb-T87pjPL7"),
		rulebuilder.NoMatch("false positive 27", `<entry key="jetbrains.mps.v8_elimination" value="executed" />`),
		rulebuilder.NoMatch("false positive 28", "minisat-master-keying:x64-uwp=fail"),
		rulebuilder.NoMatch("false positive 29", "IceSSL.KeyFile=s_rsa1024_priv.pem"),
		rulebuilder.NoMatch("false positive 30", `"bucket_key": "SalesResults-1.2"`),
		rulebuilder.NoMatch("false positive 31", `<key tag="SecurityIdentifier" name="SecurityIdentifier" type="STRING" />`),
		rulebuilder.NoMatch("`packageKey\":` + newPlausibleSecret(`[a-zA-Z0-9\\-_.=]{30}`),", "schemaKey = 'DOC_Vector_5_32'"),
		rulebuilder.NoMatch("false positive 32", `sequenceKey = "18"`),
		rulebuilder.NoMatch("false positive 33", "app.keystore.file=env/cert.p12"),
		rulebuilder.NoMatch("false positive 34", "-DKEYTAB_FILE=/tmp/app.keytab"),
		rulebuilder.NoMatch("false positive 35", "\tdoc.Security.KeySize = PdfEncryptionKeySize.Key128Bit;"),
		rulebuilder.NoMatch("false positive 36", "o.keySelector=n,o.haKey=!1,"),
		rulebuilder.NoMatch("false positive 37", `                                "key_name": "prod5zyxlmy-cmk",`),
		rulebuilder.NoMatch("false positive 38", `                                "kms_key_id": "555ea4a3-d53a-4412-9c66-3a7cb667b0d6",`),
		rulebuilder.NoMatch("false positive 39", "\t\"key_vault_name\": \"web21prqodx24021\","),
		rulebuilder.NoMatch("e.g., https://github.com/2uasimojo/community-operators-prod/blob/9e51e4c8e0b5caaa3087e8e18e6fb918b2c36643/operators/azure-service-operator/1.0.59040/manifests/azure.microsoft.com_cosmosdbs.yaml#L50", "  keyVaultToStoreSecrets: cmp2-qat-1208358310"),
		rulebuilder.NoMatch("false positive 40", `,apiKey:"6fe4476ee5a1832882e326b506d14126",`),
		rulebuilder.NoMatch("cgo constant", "AUTHTYPE_FILS_SK_PFS                            = C.NL80211_AUTHTYPE_FILS_SK_PFS"),
		rulebuilder.NoMatch("ssh key algorithm", `KeyAlgoECDSA256    = "ecdsa-sha2-nistp256"`),
		rulebuilder.NoMatch("false positive 41", `const validKeyChars = "0123456789abcdefghijklmnopqrstuvwxyz_-."`),
		rulebuilder.NoMatch("false positive 42", `const keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"`),
		rulebuilder.NoMatch("false positive 43", "key_length = XSalsa20.key_length"),
		rulebuilder.NoMatch("false positive 44", `pub const SN_id_Gost28147_89_None_KeyMeshing = "id-Gost28147-89-None-KeyMeshing"`),
		rulebuilder.NoMatch("false positive 45", "KeyPair = X25519.KeyPair"),
		rulebuilder.NoMatch("false positive 46", "BlindKeySignatures = Ed25519.BlindKeySignatures"),
		rulebuilder.NoMatch("false positive 47", `AVEncVideoMaxKeyframeDistance, "2987123a-ba93-4704-b489-ec1e5f25292c"`),
		rulebuilder.NoMatch("false positive 48", "            keyPressed = kVK_Return.u16"),
		rulebuilder.NoMatch("https://github.com/gitleaks/gitleaks/issues/1799", "timezone_mapping = {\n    \"Turkey Standard Time\": \"Europe/Istanbul\",\n}"),
		rulebuilder.NoMatch("Password", "password combination.\n\nR5: Regulatory--21"),
		rulebuilder.NoMatch("false positive 49", "PuttyPassword=0"),
		rulebuilder.NoMatch("Secret", `LLM_SECRET_NAME = "NEXUS-GPT4-API-KEY"`),
		rulebuilder.NoMatch("false positive 50", "  <UserSecretsId>79a3edd0-2092-40a2-a04d-dcb46d5ca9ed</UserSecretsId>"),
		rulebuilder.NoMatch("false positive 51", "secret_length = X25519.secret_length"),
		rulebuilder.NoMatch("false positive 52", "secretSize must be >= XXH3_SECRET_SIZE_MIN"),
		rulebuilder.NoMatch("false positive 53", "# get build time secret for authentication\n#RUN --mount=type=secret,id=jfrog_secret \\\n#    JFROG_SECRET = $(cat /run/secrets/jfrog_secret) && \\"),
		rulebuilder.NoMatch("Token", "    access_token_url='https://github.com/login/oauth/access_token',"),
		rulebuilder.NoMatch("false positive 54", `publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`),
		rulebuilder.NoMatch("false positive 55", `<SourceFile SourceLocation="F:\Extracts\" TokenFile="RTL_INST_CODE.cer">`),
		rulebuilder.NoMatch("false positive 56", `notes            = "Maven - io.jsonwebtoken:jjwt-jackson-0.11.2"`),
		rulebuilder.NoMatch("false positive 57", "csrf-token=Mj2qykJO5rELyHgezQ69nzUX0i3OH67V7+V4eUrLfpuyOuxmiW9rhROG/Whikle15syazJOkrjJa3U2AbhIvUw=="),
		rulebuilder.NoMatch("General", `clientId = "73082700-1f09-405b-80d0-3131bfd6272d"`),
		rulebuilder.NoMatch("false positive 58", "GITHUB_API_KEY=\nDYNATRACE_API_KEY="),
		rulebuilder.NoMatch("false positive 59", "snowflake.password=\njdbc.snowflake.url="),
		rulebuilder.NoMatch("false positive 60", "import { chain_Anvil1_Key, chain_Anvil2_Key } from '../blockchain-tests/pallets/supported-chains/consts';"),
		rulebuilder.NoMatch("Yocto/BitBake", `SRCREV_moby = "43fc912ef59a83054ea7f6706df4d53a7dea4d80"`),
		rulebuilder.NoMatch("false positive 61", `LIC_FILES_CHKSUM = "file://${WORKDIR}/license.html;md5=5c94767cedb5d6987c902ac850ded2c6"`),
	}
	return r
}
