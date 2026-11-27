package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "maptiler-api-key",
	Confidence:  "medium",
	Description: "Detected a MapTiler API key, which may allow access to MapTiler Cloud mapping and tile APIs.",
	Regex:       rulebuilder.Assignment([]string{"maptiler", "map_tiler", "map\\-tiler"}, `[A-Za-z0-9]{20}`),
	Keywords:    []string{"maptiler", "map_tiler", "map-tiler"},
	ValidateExpr: `let r = http.get("https://api.maptiler.com/weather/latest.json?" + "key=" + strings.urlQueryEscape(finding["secret"]), {});
(r.status in [200]) ? {"result": "valid"} :
(r.status in [403]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `maptiler = "sFSs7DzWTqRo4ceWwuNt"`, `sFSs7DzWTqRo4ceWwuNt`),
		rulebuilder.NoMatch("near miss 1", `maptiler = "D7FOY8LwPwQYv6iQmc5"`),
		rulebuilder.NoMatch("near miss 2", `maptiler = "zoXh1rYGA5Sfitc41ykrd"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "maptiler-api-key-url",
	Confidence:  "medium",
	Description: "Detected a MapTiler API key, which may allow access to MapTiler Cloud mapping and tile APIs.",
	Regex:       `(?i:\b(?:[a-z0-9-]+\.)*maptiler\.com)(?::[0-9]{1,5})?(?:/[^\s'\"\x60<>?#]{0,300})?\?(?:[^\s'\"\x60<>#]{0,300}&)?(?i:key)=([A-Za-z0-9]{20})(?:[&#'\"\x60\s\\)]|$)`,
	Keywords:    []string{"maptiler.com"},
	ValidateExpr: `let r = http.get("https://api.maptiler.com/weather/latest.json?" + "key=" + strings.urlQueryEscape(finding["secret"]), {});
(r.status in [200]) ? {"result": "valid"} :
(r.status in [403]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1 in a url", `fetch(https://api.maptiler.com/v1/resource?key=sFSs7DzWTqRo4ceWwuNt)`, `sFSs7DzWTqRo4ceWwuNt`),
		rulebuilder.Match("after another parameter", `src = "https://api.maptiler.com/v1/resource?format=json&key=sFSs7DzWTqRo4ceWwuNt"`, `sFSs7DzWTqRo4ceWwuNt`),
		rulebuilder.NoMatch("another host", `fetch(https://api.maptiler.com.example.io/v1?key=sFSs7DzWTqRo4ceWwuNt)`),
		rulebuilder.NoMatch("near miss 1", `fetch(https://api.maptiler.com/v1/resource?key=D7FOY8LwPwQYv6iQmc5)`),
		rulebuilder.NoMatch("near miss 2", `fetch(https://api.maptiler.com/v1/resource?key=zoXh1rYGA5Sfitc41ykrd)`),
	},
})
