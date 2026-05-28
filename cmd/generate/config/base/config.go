package base

import "github.com/betterleaks/betterleaks/config"

const GlobalPrefilter = `matchesAny(attributes[?"path"].orValue(""), [
  r"""gitleaks\.toml""",
  r"""(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$""",
  r"""(?i)\.(?:eot|[ot]tf|woff2?)$""",
  r"""(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$""",
  r"""go\.(?:mod|sum|work(?:\.sum)?)$""",
  r"""(?:^|/)vendor/modules\.txt$""",
  r"""(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$""",
  r"""(?:^|/)gradlew(?:\.bat)?$""",
  r"""(?:^|/)gradle\.lockfile$""",
  r"""(?:^|/)mvnw(?:\.cmd)?$""",
  r"""(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$""",
  r"""(?:^|/)node_modules(?:/.*)?$""",
  r"""(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$""",
  r"""(?:^|/)bower_components(?:/.*)?$""",
  r"""(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$""",
  r"""(?:^|/)javascript\.json$""",
  r"""(?:^|/)(?:Pipfile|poetry)\.lock$""",
  r"""(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$""",
  r"""(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$""",
  r"""(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$""",
  r"""(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$""",
  r"""\.gem$""",
  r"""verification-metadata\.xml""",
  r"""Database.refactorlog""",
  r"""(?:^|/)\.git$"""
])
`

const GlobalFilter = `(matchesAny(finding["secret"], [
  r"""(?i)^true|false|null$""",
  r"""^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$""",
  r"""^\$(?:\d+|{\d+})$""",
  r"""^\$(?:[A-Z_]+|[a-z_]+)$""",
  r"""^\${(?:[A-Z_]+|[a-z_]+)}$""",
  r"""^\{\{[ \t]*[\w ().|]+[ \t]*}}$""",
  r"""^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*}}$""",
  r"""^%(?:[A-Z_]+|[a-z_]+)%$""",
  r"""^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$""",
  r"""^\{\d{0,2}}$""",
  r"""^@(?:[A-Z_]+|[a-z_]+)@$""",
  r"""^/Users/(?i)[a-z0-9]+/[\w .-/]+$""",
  r"""^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$"""
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
