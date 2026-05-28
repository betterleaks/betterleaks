package rules

import (
	"strconv"
	"strings"
)

const genericAPIKeyMatchFilter = `(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))`

var genericAPIKeyFilter = buildGenericAPIKeyFilter()

func buildGenericAPIKeyFilter() string {
	return `matchesAny(finding["secret"], [r"""^[a-zA-Z_.-]+$"""])
|| (matchesAny(finding["match"], [r"""` + genericAPIKeyMatchFilter + `"""]) || containsAny(finding["secret"], ` + celStringList(DefaultStopWords) + `))
|| matchesAny(finding["line"], [
  r"""--mount=type=secret,""",
  r"""import[ \t]+{[ \t\w,]+}[ \t]+from[ \t]+['"][^'"]+['"]"""
])
|| (matchesAny(attributes[?"path"].orValue(""), [
  r"""\.bb$""",
  r"""\.bbappend$""",
  r"""\.bbclass$""",
  r"""\.inc$"""
]) && matchesAny(finding["line"], [
  r"""LICENSE[^=]*=\s*"[^"]+""",
  r"""LIC_FILES_CHKSUM[^=]*=\s*"[^"]+""",
  r"""SRC[^=]*=\s*"[a-zA-Z0-9]+"""
]))`
}

func celStringList(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = strconv.Quote(s)
	}
	if len(parts) <= 1 {
		return "[" + strings.Join(parts, ", ") + "]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for i, p := range parts {
		b.WriteString("  " + p)
		if i < len(parts)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteByte(']')
	return b.String()
}
