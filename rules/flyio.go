package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://fly.io/docs/security/tokens/
// https://github.com/trufflesecurity/trufflehog/pull/2381/files#r1565860579
// https://github.com/superfly/macaroon-elixir/blob/8b42043b0a24aada5c8b8eb8505dbf1590557f1b/test/vectors.json#L7
var _ = rulebuilder.Add(config.Rule{
	ID:          "flyio-access-token",
	Confidence:  "high",
	Description: "Uncovered a Fly.io API key", // TODO
	Regex:       rulebuilder.Token(`FlyV1\s[A-Za-z0-9=_\-,/+]{100,}`),
	Keywords:    []string{"flyv1"},
	ValidateExpr: `let r = http.post("https://api.fly.io/graphql", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"query\": \"query { viewer { id email name } }\"}"); r.status == 200 && (r.body contains "\"data\"") && (r.body contains "\"viewer\"") && (r.body contains "\"email\"") ? {
    "result": "valid",
    "metadata": {"email": (r.json?.data?.viewer?.email ?? ""), "name": (r.json?.data?.viewer?.name ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `flyToken = "FlyV1 ,f/zhT9VcgTAaKFD7lxezyJ=z/U06QSVbMGNG3dm,iDQ5QisMG,tSMkORDUjzHOkDZlHM2QoDyUiWU0NUx5,dUG/UeyF-f0fNrCm"`, "FlyV1 ,f/zhT9VcgTAaKFD7lxezyJ=z/U06QSVbMGNG3dm,iDQ5QisMG,tSMkORDUjzHOkDZlHM2QoDyUiWU0NUx5,dUG/UeyF-f0fNrCm"),
		rulebuilder.Match("true positive 1", `ENV FLY_API_TOKEN="FlyV1 fm1r_lJPECAAAAAAAAMqcxBBLMJKXYKJiT0CI58XmukX/wrVodHlwczovL2FwaS5mbHkuaW8vdjGWAJLOAAFmXh8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDy5OfA2M6K6aLEoEDKxehojbj+8ZT9IrXCF5sL/r8m6/1gylwySsNxpD40wnpd/G2ZdjwVaQev1kEuFUgzERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry5AaXiroRdjrSsFExc/xRCDZKUA5GBzgATuNsfBZGCp2J1aWxkZXIfondnHwHEIMa6NWc4b52S+UY7vjPdwKrz00Uzrc1830mOHzQNLun7,fm1a_lJPERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry4AaXiroRdjrSsFExc/xRCxBCVlAoRzKV/+qYkxuipIbIcw7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxlgSSzmS4Y7nPAAAAASCwgdcKkc4AAUktDMQQURck2h+upbiOrW66Nf5SA8QgrD03xlWju1WQi0AUhlk7YYFzOLDfhRyJ6nEziO37NUE="`, "FlyV1 fm1r_lJPECAAAAAAAAMqcxBBLMJKXYKJiT0CI58XmukX/wrVodHlwczovL2FwaS5mbHkuaW8vdjGWAJLOAAFmXh8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDy5OfA2M6K6aLEoEDKxehojbj+8ZT9IrXCF5sL/r8m6/1gylwySsNxpD40wnpd/G2ZdjwVaQev1kEuFUgzERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry5AaXiroRdjrSsFExc/xRCDZKUA5GBzgATuNsfBZGCp2J1aWxkZXIfondnHwHEIMa6NWc4b52S+UY7vjPdwKrz00Uzrc1830mOHzQNLun7,fm1a_lJPERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry4AaXiroRdjrSsFExc/xRCxBCVlAoRzKV/+qYkxuipIbIcw7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxlgSSzmS4Y7nPAAAAASCwgdcKkc4AAUktDMQQURck2h+upbiOrW66Nf5SA8QgrD03xlWju1WQi0AUhlk7YYFzOLDfhRyJ6nEziO37NUE="),
		rulebuilder.Match("true positive 2", "#           FLY_API_TOKEN: FlyV1 fm2_lJPECAAAAAAAAyZtxBD1hSZ7L5leXsj64ZbDlkm/wrVodHRwczovL2FwaS5mbHkuaW8vdjGWAJLOAAwMDB8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDwDnhgJj/ML/nRKMiAYgnvXfNacrGWffj5TdfgGY2LU0ZetT7WzTLQQMO8cN2nRTztl/xLjnnZg5pBwFonETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAiR273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwjw2SlAORgc4APu7vHwWRgqdidWlsZGVyH6J3Zx8BxCAlmLbu1HQDg8ZAGKKmEt4Mbnbqli6lbzBDHsawhcUF4A==,fm2_lJPETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAij273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwj8QQbn07DOV+7SmoLj/uT+dbr8O5aHR0cHM6Ly9hcGkuZmx5LmlvL2FhYS92MZgEks5mqfbvzwAAAAE9PYz9F84AC7QACpHOAAu0AAzEEFfW3B+SzffV/KrAYa8qqpnEIIlD6DqZMZQ9Kt7fEenCCOLA+tUSJ+kmEFIUcc83npOI", "FlyV1 fm2_lJPECAAAAAAAAyZtxBD1hSZ7L5leXsj64ZbDlkm/wrVodHRwczovL2FwaS5mbHkuaW8vdjGWAJLOAAwMDB8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDwDnhgJj/ML/nRKMiAYgnvXfNacrGWffj5TdfgGY2LU0ZetT7WzTLQQMO8cN2nRTztl/xLjnnZg5pBwFonETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAiR273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwjw2SlAORgc4APu7vHwWRgqdidWlsZGVyH6J3Zx8BxCAlmLbu1HQDg8ZAGKKmEt4Mbnbqli6lbzBDHsawhcUF4A==,fm2_lJPETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAij273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwj8QQbn07DOV+7SmoLj/uT+dbr8O5aHR0cHM6Ly9hcGkuZmx5LmlvL2FhYS92MZgEks5mqfbvzwAAAAE9PYz9F84AC7QACpHOAAu0AAzEEFfW3B+SzffV/KrAYa8qqpnEIIlD6DqZMZQ9Kt7fEenCCOLA+tUSJ+kmEFIUcc83npOI"),
		rulebuilder.Match("true positive 3", `"BindToParentToken": "FlyV1 fm2_lJPEEKnzKy0lkwV3B+WIlmrdwejEEFv5qmevHU4fMs+2Gr6oOiPC2SAyOTc0NWI4ZmJlNjBlNjJmZTgzNTkxOThhZWE4MjY0M5IMxAMBAgPEIH7VG8u74KwO62hmx8SZO8WaU5o1g3W2IVc7QN6T1VTr",`, "FlyV1 fm2_lJPEEKnzKy0lkwV3B+WIlmrdwejEEFv5qmevHU4fMs+2Gr6oOiPC2SAyOTc0NWI4ZmJlNjBlNjJmZTgzNTkxOThhZWE4MjY0M5IMxAMBAgPEIH7VG8u74KwO62hmx8SZO8WaU5o1g3W2IVc7QN6T1VTr"),
		rulebuilder.Match("bare secret", "FlyV1 xFMqk5,_2N0K6hJc5RFJVXCYqXBg5Ij8SXoLkemJAl6gM4rZ/PiECfCx5UdESWsXxjNdMcFBfHd/7S1FE97qNasTnp+J1XhHkBJLl4dLhQJm8V2MfO3YFhEVwQyXlL8wJz/dj", "FlyV1 xFMqk5,_2N0K6hJc5RFJVXCYqXBg5Ij8SXoLkemJAl6gM4rZ/PiECfCx5UdESWsXxjNdMcFBfHd/7S1FE97qNasTnp+J1XhHkBJLl4dLhQJm8V2MfO3YFhEVwQyXlL8wJz/dj"),
		rulebuilder.NoMatch("low entropy", "FlyV1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
