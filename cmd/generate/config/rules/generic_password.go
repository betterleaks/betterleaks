package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericPassword() *config.Rule {
	passwordAssignmentRegex := `(?:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{4,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]+(?:#|//|/\*|--)|[ \t]*$|\\[nr])`
	authArgumentRegex := `\b(?:login|log_in|authenticate)\b[ \t]*\([ \t]*[^,()\r\n]{1,250}[ \t]*,[ \t]*(?:"((?:\\.|[^"\\\r\n]){4,250})"|'((?:\\.|[^'\\\r\n]){4,250})'|\x60((?:\\.|[^\x60\\\r\n]){4,250})\x60)[ \t]*\)`

	r := config.Rule{
		RuleID:      "generic-password",
		Confidence:  "low",
		Description: "Detected a potential hardcoded password literal, which may expose account credentials.",
		Regex:       regexp.MustCompile(`(?i)(?:` + passwordAssignmentRegex + `|` + authArgumentRegex + `)`),
		Keywords: []string{
			"passw", "psw", "_pw", "-pw", ".pw",
			"login(", "login (",
			"log_in(", "log_in (",
			"authenticate(", "authenticate (",
		},
		Specificity: 20,
		Components: []*config.Component{
			{
				RuleID:   "generic-username",
				Optional: true,
				Within:   "7L,200C",
			},
		},
		Filter: `// Restrict nearby evidence to the password's line and the
// six lines on either side. The password key itself is intentionally excluded
// from the evidence patterns below.
let raw = finding["fragment_raw"];
let beforeLines = split(raw[
  max(finding["match_start_idx"] - 8192, 0):finding["match_start_idx"]
], "\n");
let afterLines = split(raw[
  finding["match_end_idx"]:min(finding["match_end_idx"] + 8192, len(raw))
], "\n");
let nearbyContext =
  join(beforeLines[max(len(beforeLines) - 7, 0):], "\n")
  + "\n"
  + join(afterLines[:min(len(afterLines), 7)], "\n");
let linePrefix = beforeLines[len(beforeLines) - 1];

let hasAuthContext = filter.matchesAny(nearbyContext, [
  // Authentication and connection calls.
  ` + "`(?i)(?:^|[^a-z0-9])(?:auth(?:enticate|entication)?|login|log[_.-]?in|sign[_.-]?in|connect(?:ion)?|open[_.-]?(?:connection|session)|create[_.-]?(?:connection|session)|bind)\\b[ \\t]*\\(`" + `,
  // Credential and connection configuration containers.
  ` + "`(?i)(?:^|[^a-z0-9])(?:basic[_.-]?auth|auth(?:entication)?[_.-]?(?:config|options|params)|credentials?|login[_.-]?(?:config|options|params)|connection[_.-]?(?:string|config|options|params)|data[_.-]?source|dsn)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:|\\{|\\()`" + `,
  // Assets commonly paired with credentials.
  ` + "`(?i)(?:^|[^a-z0-9])(?:host(?:name)?|server|endpoint|database|db[_.-]?(?:name|host|url)?|port|jdbc[_.-]?url|connection[_.-]?url)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}(?:\"[^\"\\r\\n]+\"|'[^'\\r\\n]+'|\\x60[^\\x60\\r\\n]+\\x60|[^\\s,;)}\\]]+)`" + `,
  // Nearby connection URI or service context.
  ` + "`(?i)\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqps?|ldaps?|smtps?|ftps?|ssh)://`" + `
]);
let hasIdentityFieldContext = filter.matchesAny(nearbyContext, [
  ` + "`(?im)(?:^|[^a-z0-9])(?:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)`" + `
]);
let isDirectAuthArgument = filter.matchesAny(finding["match"], [
  ` + "`(?i)^(?:login|log_in)\\b[ \\t]*\\(`" + `,
  ` + "`(?i)^authenticate\\b[ \\t]*\\([ \\t]*[^,\\r\\n]*(?:user(?:name)?|account|email|login|uid)[^,\\r\\n]*,`" + `
]);
let isCommented = filter.matchesAny(linePrefix, [
  ` + "`(?:^[ \\t]*(?:#|//|/\\*|\\*|--|;|<!--)|[ \\t](?:#|//|/\\*|--|<!--)[ \\t]*)`" + `
]);
let isInstructionalPlaceholder = filter.matchesAny(finding["secret"], [
  ` + "`^(?:PGPASSWORD|[A-Z][A-Z0-9_]*_(?:PASSWORD|PASSWD|PWD)(?:_[A-Z0-9]+)*|(?:PASSWORD|PASSWD|PWD)_[A-Z0-9_]+)$`" + `,
  ` + "`(?i)^(?:(?:(?:an?|my)[ _.-]*)?example(?:[ _.-]*(?:password|passwd|pwd))?|(?:password|passwd|pwd)[ _.-]*example)(?:[ _.-]*[0-9]{1,4})?[!?.]*$`" + `,
  ` + "`(?i)^(?:password|passwd|pwd)?[ _-]?(?:goes[ _-]?here|replace[ _-]?me|insert[ _-].*here|not[ _-]?set)$`" + `
]);
let isCodeFile = filter.matchesAny(attributes["path"], [
  ` + "`(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`" + `
]);
let isUnquotedAssignment = filter.matchesAny(finding["match"], [
  ` + "`^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`" + `
]);
let isUnquotedCodeValue = isCodeFile && isUnquotedAssignment;
let isUnquotedExpression = isUnquotedAssignment && filter.matchesAny(finding["secret"], [
  ` + "`^[A-Za-z_][A-Za-z0-9_-]*:\\[[^]\\r\\n]+\\]$`" + `,
  ` + "`^[A-Za-z_][A-Za-z0-9_]*[)}\\]]+(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*(?:\\([^)]*\\))?)*$`" + `
]);
let hasNonPlaintextPasswordContext = filter.matchesAny(linePrefix + finding["match"], [
  ` + "`(?i)(?:^|[^a-z0-9])(?:enc|encrypt(?:ed|ion)?|hash(?:ed)?|encod(?:e|ed|ing)|cipher(?:text)?|seal(?:ed)?|vault(?:ed)?)(?:[_.-][a-z0-9]+){0,5}[_.-]?password\\b`" + `,
  ` + "`(?i)(?:^|[^a-z0-9])password[_.-]?(?:cipher(?:text)?|hash|digest|algorithm|scheme|encoding|format)\\b`" + `
]);
let hasNestedUnquotedAssignment = filter.matchesAny(finding["match"], [
  ` + "`^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}[^\"'\\x60\\r\\n]*[.,][A-Za-z_][A-Za-z0-9_-]*=`" + `
]);
let isEncryptedValue = filter.matchesAny(finding["secret"], [
  // Serialized encryption envelopes and armored ciphertext.
  ` + "`(?i)^ENC\\[[A-Z0-9][A-Z0-9_.+/-]*(?:,|\\]|$)`" + `,
  ` + "`(?i)^ENC\\([A-Z0-9+/=_:.,-]{8,}\\)$`" + `,
  ` + "`(?i)^\\{cipher\\}.{4,}$`" + `,
  ` + "`^\\$ANSIBLE_VAULT(?:;|$)`" + `,
  ` + "`(?i)^!vault$`" + `,
  ` + "`^age-encryption\\.org/v[0-9]+$`" + `,
  ` + "`^-----BEGIN (?:AGE ENCRYPTED FILE|PGP MESSAGE|ENCRYPTED PRIVATE KEY)-----$`" + `,
  // OpenSSL salted output, HashiCorp Vault transit ciphertext, and Fernet.
  ` + "`^U2FsdGVkX1[A-Za-z0-9+/=]{8,}$`" + `,
  ` + "`^vault:v[0-9]+:[A-Za-z0-9+/=_-]{8,}$`" + `,
  ` + "`^gAAAAA[A-Za-z0-9_-]{70,}={0,2}$`" + `,
  // Compact JWE and encrypted PASETO (local-purpose) tokens.
  ` + "`^[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}$`" + `,
  ` + "`^v[124]\\.local\\.[A-Za-z0-9_-]{32,}(?:\\.[A-Za-z0-9_-]+)?$`" + `,
  // Windows DPAPI blobs in Base64 or exported SecureString hex form.
  ` + "`^AQAAANCMnd8BFdERjHoAwE/Cl\\+sBA[A-Za-z0-9+/=]{16,}$`" + `,
  ` + "`(?i)^01000000d08c9ddf0115d1118c7a00c04fc297eb01[0-9a-f]{16,}$`" + `
]);
let isCryptographicAlgorithm = filter.matchesAny(finding["secret"], [
  // Common block ciphers with key sizes and/or modes.
  ` + "`(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:128|192|256)(?:[-_/](?:ECB|CBC(?:[-_/]HMAC[-_/]SHA[-_]?(?:256|384|512))?|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP))?$`" + `,
  ` + "`(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)$`" + `,
  ` + "`(?i)^(?:(?:RIJNDAEL|ARIA|CAMELLIA|DES(?:[-_]?(?:EDE3?|3|X))?|DESEDE|3DES|TRIPLE[-_]?DES|BLOWFISH|BF|TWOFISH|SERPENT|CAST(?:5|128|256)?|IDEA|SEED|SM4|RC[2456]|ARCFOUR)[-_/](?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)|X?(?:CHACHA20|SALSA20)[-_/]POLY1305|AESWRAP(?:[-_]?(?:128|192|256))?|DESEDEWRAP)$`" + `,
  // Java Cryptography Architecture transformations and PBE names.
  ` + "`(?i)^(?:AES(?:[-_]?(?:128|192|256))?|ARIA(?:[-_]?(?:128|192|256))?|CAMELLIA(?:[-_]?(?:128|192|256))?|BLOWFISH|DES|DESEDE|RC2|RSA)/(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM)/(?:NO|PKCS[157]|ISO10126|OAEPWITH(?:MD5|SHA[-_]?(?:1|224|256|384|512))ANDMGF1)PADDING$`" + `,
  ` + "`(?i)^PBEWITH(?:HMAC)?(?:MD5|SHA(?:1|224|256|384|512))AND(?:AES(?:[-_]?(?:128|256))?|DES(?:EDE)?|TRIPLEDES|RC[24](?:[-_]?(?:40|128))?)$`" + `,
  // JOSE/JWE key-management and content-encryption identifiers.
  ` + "`(?i)^(?:RSA1_5|RSA-OAEP(?:-(?:256|384|512))?|ECDH-ES(?:\\+A(?:128|192|256)(?:GCM)?KW)?|A(?:128|192|256)(?:KW|GCMKW|GCM|CBC-HS(?:256|384|512))|PBES2-HS(?:256|384|512)\\+A(?:128|192|256)KW)$`" + `,
  // Other explicit asymmetric encryption and key-wrapping descriptors.
  ` + "`(?i)^(?:RSA(?:ES)?[-_/](?:OAEP(?:[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)))?|PKCS1(?:[-_]?V?1[_.]5)?|NO[-_]?PADDING)|ECIES(?:[-_/](?:P(?:256|384|521)|SECP(?:256K1|256R1|384R1|521R1)))?|ELGAMAL[-_/](?:ECB|OAEP|PKCS1)|SM2[-_/](?:C1C2C3|C1C3C2))$`" + `,
  // Composite hash, MAC, signature, and password-derivation identifiers.
  ` + "`(?i)^(?:HMAC[-_]?(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|PBKDF2[-_/](?:HMAC[-_]?)?(?:SHA[-_]?(?:1|224|256|384|512))|HKDF[-_/]SHA[-_]?(?:1|224|256|384|512)|(?:RSA|DSA|ECDSA|ED25519)[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))[-_/](?:RSA|DSA|ECDSA|ED25519))$`" + `,
  // TLS and OpenSSH cipher-suite identifiers.
  ` + "`(?i)^TLS_(?:(?:AES_(?:128|256)_GCM|CHACHA20_POLY1305)_SHA(?:256|384)|[A-Z0-9]+(?:_[A-Z0-9]+)*_WITH_[A-Z0-9]+(?:_[A-Z0-9]+)*)$`" + `,
  ` + "`(?i)^(?:AES(?:128|192|256)-(?:CBC|CTR|GCM)|CHACHA20-POLY1305)@OPENSSH\\.COM$`" + `
]);
let isContextualAlgorithmName = hasNonPlaintextPasswordContext && filter.matchesAny(finding["secret"], [
  // A field name can disambiguate an exact algorithm name, but cannot by
  // itself prove that an arbitrary value is encrypted or hashed.
  ` + "`(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA|CHACHA20|XCHACHA20|SALSA20|XSALSA20|DES|DESEDE|3DES|TRIPLE[-_]?DES|TWOFISH|SERPENT|CAST(?:5|128|256)|IDEA|SEED|SM4|RC[2456]|ARCFOUR|RSA|ECIES|ELGAMAL|SM2|MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512)|BLAKE2[BS](?:[-_]?(?:256|512))?|BLAKE3|RIPEMD[-_]?(?:128|160|256|320)|WHIRLPOOL|SM3|PBKDF2|SCRYPT|BCRYPT|ARGON2(?:D|I|ID)?|HKDF|YESCRYPT)$`" + `
]);
let level = (
  (
    isDirectAuthArgument
    || (hasAuthContext && hasIdentityFieldContext)
  )
  && !isCommented
  && !isInstructionalPlaceholder
) ? "medium" : "low";
let _ = filter.setConfidence(level);

filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
  ` + "`(?i)^x{4,}$`" + `,
  ` + "`(?i)^\\[?(?:redacted|masked|filtered)\\]?$`" + `,
  ` + "`^•+$`" + `,
  ` + "`^\\$\\{.*}$`" + `,
  ` + "`^\\$\\([^\\r\\n]+\\)$`" + `,
  ` + "`^#\\{[^}\\r\\n]+}$`" + `,
  ` + "`^\\{\\{[ \\t]*.+[ \\t]*}}$`" + `,
  ` + "`^%\\{[^}]+}$`" + `,
  ` + "`^\\$[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`(?i)^\\$env:[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`^%[A-Za-z_][A-Za-z0-9_]*%$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^<[^>\\s]+$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`(?i)^(?:your[_-]?password|placeholder|forbidden_value)$`" + `,
  ` + "`^\\([A-Za-z_][A-Za-z0-9_.]*(?:[ \\t]+[A-Za-z_][A-Za-z0-9_.]*)*\\)$`" + `,
  ` + "`^\\$\\(`" + `,
  ` + "`(?:\\$\\{|#\\{|\\{\\{|%\\{)`" + `,
  ` + "`%\\([A-Za-z_][A-Za-z0-9_]*\\)[#0 +\\-]?[0-9.]*(?:[diouxXeEfFgGcrs%])`" + `,
  ` + "`(?i)^--?passw(?:or)?d$`" + `,
  ` + "`^\\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{7,}$`" + `,
  ` + "`(?i)^\\$pbkdf2[-_][^$]+\\$.*$`" + `,
  ` + "`(?i)^(?:pbkdf2_(?:sha1|sha256)|bcrypt_sha256|argon2|scrypt|sha1|md5|crypt)\\$`" + `,
  ` + "`(?i)^\\$(?:1|5|6|7|y|gy|argon2(?:d|i|id)|scrypt|pbkdf2(?:[-_]sha(?:1|224|256|384|512))?|apr1)\\$`" + `,
  ` + "`^\\$[PH]\\$[./A-Za-z0-9]{20,}$`" + `,
  ` + "`(?i)^\\{(?:SSHA(?:256|384|512)?|SHA(?:256|384|512)?|MD5|CRYPT|BCRYPT|PBKDF2)}`" + `,
  ` + "`(?i)^SCRAM-SHA-(?:1|256|512)\\$`" + `,
  ` + "`(?i)^md5[0-9a-f]{32}$`" + `,
  ` + "`^\\*[0-9A-F]{40}$`" + `
])
|| isEncryptedValue
|| isCryptographicAlgorithm
|| isContextualAlgorithmName
|| isUnquotedCodeValue
|| isUnquotedExpression
|| hasNestedUnquotedAssignment
|| filter.matchesAny(finding["match"], [
  ` + "`^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|psw|token|secret|hex)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		`password: hunter2`,
		`password: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB`,
		`password = "the quick brown fox jumps over lazy dogs"`,
		`password = "MyPassword123!"`,
		`password = "myAES256_GCMpassword"`,
		`password = "rsa-admin-2026"`,
		`password = "sha256-is-not-my-password"`,
		`encrypted_password: "hunter2"`,
		`enc_password: "hunter2"`,
		`vault_password: "hunter2"`,
		`encrypted_password: "Blowfish"`,
		`password = "hunter2" # development password`,
		`password = "hunter2" // TODO: move to vault`,
		`password: "hunter2" -- local database`,
		`password = "PASSWORD"`,
		"credentials: {\nusername: alice\npassword: hunter2\n}",
		"USERNAME=alice@example.com\nPASSWORD=hunter2",
		"login({\nusername = process.env.USERNAME\npasswd = \"g4F!mQ8#vZ2@rT6$xK9\"\n})",
		"auth_config: {\npsw: hunter2\n}",
		"database.host = db.internal\ndatabase_pw = \"J8s!vR4#qL7@nT2$xM6\"",
		"service.connect(\n  service-pw: Qv7D0LXCM3EIMbgJpUNnkRtOfOueHznB\n)",
		"dsn: postgres://db.internal/app\nclient.pw = \"m4F!qK8#zR2@tV6$xN9\"",
		"login({\n  \"password\": \"#exFfrbtEpo&RaTkZ#%*zFgS\"\n})",
		`smtp.login(username, "hunter2")`,
		`login(user, "root")`,
		`login(user, "PASSWD")`,
		`client.authenticate(user, "password1")`,
		`client.authenticate(request, "basic")`,
		`service.log_in(account, 'correct horse battery staple')`,
	}
	fps := []string{
		`password: four`,
		"username: alice\npassword = process.env.PASSWORD",
		"database.host = db.internal\ndatabase_pw = undefined",
		"username: alice\npassword = \"your_password\"",
		`postgres://user:hunter2@example.com/db`,
		`ldap.bind(user, "hunter2")`,
		`log.in(user, "hunter2")`,
		`log-in(user, "hunter2")`,
		`enc_sssd_sa_password: ENC[AES256_GCM,data:XYZ,iv:ABC,tag:DEF,type:str]`,
		`password: "AES-256-GCM"`,
		`password: "AES_256_CBC_HMAC_SHA_256"`,
		`password: "AES/GCM"`,
		`password: "AESWrap_256"`,
		`password: "CAMELLIA-256-CBC"`,
		`password: "ARIA_192_GCM"`,
		`password: "CHACHA20-POLY1305"`,
		`password: "XSALSA20-POLY1305"`,
		`password: "DES-EDE3-CBC"`,
		`password: "SM4-CTR"`,
		`password: "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"`,
		`password: "PBEWithHmacSHA256AndAES_256"`,
		`password: "PBES2-HS256+A128KW"`,
		`password: "$ANSIBLE_VAULT;1.2;AES256;dev"`,
		`password: "{cipher}AQB4aLongEncryptedValue"`,
		`password: "ENC(VeryLongEncryptedPayload123==)"`,
		`password: "U2FsdGVkX19hbG90b2ZjaXBoZXJ0ZXh0"`,
		`password: "vault:v1:AbCdEfGhIjKlMnOpQrStUvWxYz012345"`,
		`password: "$argon2id$v=19$m=65536,t=3,p=4$YWJj$ZGVm"`,
		`password: "SCRAM-SHA-512$4096:c2FsdA==$c3RvcmVkOnNlcnZlcg=="`,
	}
	return utils.Validate(r, tps, fps)
}

func GenericUsername() *config.Rule {
	r := config.Rule{
		RuleID:      "generic-username",
		Confidence:  "low",
		Description: "Detected a username-like value used as a component of the generic-password rule.",
		Regex:       regexp.MustCompile(`(?m)(?:^|[^a-zA-Z0-9])(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){3,250})"|'((?:\\.|[^'\\\r\n]){3,250})'|\x60((?:\\.|[^\x60\\\r\n]){3,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{2,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`),
		Keywords: []string{
			"user",
			"login",
			"email",
			"uid",
			"account",
			"client",
		},
		SkipReport: true,
		Filter: `// An unquoted value is an ambiguous scalar in configuration, but
// not a string literal in the source languages recognized below.
let isCodeFile = filter.matchesAny(attributes["path"], [
  ` + "`(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`" + `
]);
let isUnquotedCodeValue = isCodeFile && filter.matchesAny(finding["match"], [
  ` + "`^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`" + `
]);

isUnquotedCodeValue
|| filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
  ` + "`(?i)^x{4,}$`" + `,
  ` + "`^•+$`" + `,
  ` + "`^\\$\\{.*}$`" + `,
  ` + "`^\\$\\([^\\r\\n]+\\)$`" + `,
  ` + "`^#\\{[^}\\r\\n]+}$`" + `,
  ` + "`^\\{\\{[ \\t]*.+[ \\t]*}}$`" + `,
  ` + "`^%\\{[^}]+}$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^<[^>\\s]+$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`(?i)^\\[?(?:redacted|masked|filtered)\\]?$`" + `,
  ` + "`^(?:USERNAME|USER_NAME|USER|LOGIN|LOGIN_NAME|ACCOUNT_NAME|EMAIL|EMAIL_ADDRESS|UID|CLIENT|CLIENT_ID|CLIENT_NAME)$`" + `,
  ` + "`(?i)^(?:your|example)[_-]?(?:username|user_name|user|login|login_name|account_name|email|email_address|uid|client(?:_id|_name)?)$`" + `
])
|| filter.matchesAny(finding["match"], [
  ` + "`^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:username|user|login(?:_name)?|email(?:_address)?|uid|account(?:_name)?|client(?:_(?:id|name))?|id)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		`username: alice`,
		`login = "alice@example.com"`,
		`client_id: service-client`,
		`clientId: service-client`,
	}
	fps := []string{
		`user: me`,
		`username = process.env.USERNAME`,
		`username = "your_username"`,
	}
	return utils.Validate(r, tps, fps)
}
