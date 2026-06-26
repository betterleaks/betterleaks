package base

import "github.com/betterleaks/betterleaks/config"

const GlobalPrefilter = `matchesAny(get(attributes, "path", ""), [
  ` + "`gitleaks\\.toml`" + `,
  ` + "`(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`" + `,
  ` + "`(?i)\\.(?:eot|[ot]tf|woff2?)$`" + `,
  ` + "`(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$`" + `,
  ` + "`go\\.(?:mod|sum|work(?:\\.sum)?)$`" + `,
  ` + "`(?:^|/)vendor/modules\\.txt$`" + `,
  ` + "`(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$`" + `,
  ` + "`(?:^|/)gradlew(?:\\.bat)?$`" + `,
  ` + "`(?:^|/)gradle\\.lockfile$`" + `,
  ` + "`(?:^|/)mvnw(?:\\.cmd)?$`" + `,
  ` + "`(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$`" + `,
  ` + "`(?:^|/)node_modules(?:/.*)?$`" + `,
  ` + "`(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$`" + `,
  ` + "`(?:^|/)bower_components(?:/.*)?$`" + `,
  ` + "`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$`" + `,
  ` + "`(?:^|/)javascript\\.json$`" + `,
  ` + "`(?:^|/)(?:Pipfile|poetry)\\.lock$`" + `,
  ` + "`(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$`" + `,
  ` + "`(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$`" + `,
  ` + "`(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$`" + `,
  ` + "`(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$`" + `,
  ` + "`\\.gem$`" + `,
  ` + "`verification-metadata\\.xml`" + `,
  ` + "`Database.refactorlog`" + `,
  ` + "`(?:^|/)\\.git$`" + `
])
`

const GlobalFilter = `(matchesAny(finding["secret"], [
  ` + "`(?i)^true|false|null$`" + `,
  ` + "`^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$`" + `,
  ` + "`^\\$(?:\\d+|{\\d+})$`" + `,
  ` + "`^\\$(?:[A-Z_]+|[a-z_]+)$`" + `,
  ` + "`^\\${(?:[A-Z_]+|[a-z_]+)}$`" + `,
  ` + "`^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$`" + `,
  ` + "`^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$`" + `,
  ` + "`^%(?:[A-Z_]+|[a-z_]+)%$`" + `,
  ` + "`^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`" + `,
  ` + "`^\\{\\d{0,2}}$`" + `,
  ` + "`^@(?:[A-Z_]+|[a-z_]+)@$`" + `,
  ` + "`^/Users/(?i)[a-z0-9]+/[\\w .-/]+$`" + `,
  ` + "`^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$`" + `
]) || containsAny(finding["secret"], [
  "abcdefghijklmnopqrstuvwxyz",
  "014df517-39d1-4453-b7b3-9930c563627c"
]))
`

func CreateGlobalConfig() *config.Config {
	return &config.Config{
		Title:     "betterleaks config",
		Prefilter: GlobalPrefilter,
		Filter:    GlobalFilter,
	}
}
