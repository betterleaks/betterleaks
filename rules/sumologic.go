package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "sumologic-access-id",
	Confidence:  "medium",
	Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
	Regex:       rulebuilder.Assignment([]string{"(?-i:[Ss]umo|SUMO)"}, "(?i)(?-i:su)[a-zA-Z0-9]{12}"),
	Keywords: []string{
		"sumo",
	},
	FilterExpr: rulebuilder.MinEntropyAndTokenEfficiency,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sumoToken = "suRFbD56TI2smT"`, "suRFbD56TI2smT"),
		rulebuilder.Match("true positive 1", `sumologic.accessId = "su9OL59biWiJu7"`, "su9OL59biWiJu7"),
		rulebuilder.Match("true positive 2", `sumologic_access_id = "sug5XpdpaoxtOH"`, "sug5XpdpaoxtOH"),
		rulebuilder.Match("true positive 3", `export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, "suDbJw97o9WVo0"),
		rulebuilder.Match("true positive 4", `SUMO_ACCESS_ID = "suGyI5imvADdvU"`, "suGyI5imvADdvU"),
		rulebuilder.NoMatch("false positive 1", "- (NSNumber *)sumOfProperty:(NSString *)property;"),
		rulebuilder.NoMatch("false positive 2", "- (NSInteger)sumOfValuesInRange:(NSRange)range;"),
		rulebuilder.NoMatch("false positive 3", "+ (unsigned char)byteChecksumOfData:(id)arg1;"),
		rulebuilder.NoMatch("false positive 4", "sumOfExposures = sumOfExposures;"),
		rulebuilder.NoMatch("false positive 5", ".si-sumologic.si--color::before { color: #000099; }"),
		rulebuilder.NoMatch("false positive 6", "/// Based on the SumoLogic keyword syntax:"),
		rulebuilder.NoMatch("false positive 7", `sumologic_access_id         = ""`),
		rulebuilder.NoMatch("false positive 8", "SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}"),
		rulebuilder.NoMatch("false positive 9", "export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX"),
		rulebuilder.NoMatch("false positive 10", "sumObj = suGyI5imvADdvU"),
		rulebuilder.NoMatch("false positive 11", `sumologic.accessId = "SU9OL59biWiJu7"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "sumologic-access-token",
	Confidence:  "medium",
	Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
	Regex:       rulebuilder.Assignment([]string{"(?-i:[Ss]umo|SUMO)"}, `(?i)`+rulebuilder.AlphaNumeric("64")),
	Keywords: []string{
		"sumo",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sumoToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
		rulebuilder.Match("true positive 1", `export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, "3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"),
		rulebuilder.Match("true positive 2", "SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk", "gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk"),
		rulebuilder.Match("true positive 3", "SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7", "9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7"),
		rulebuilder.Match("true positive 4", `sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`, "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"),
		rulebuilder.NoMatch("false positive 1", "#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("false positive 2", "-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`"),
		rulebuilder.NoMatch("false positive 3", "SUMO_ACCESS_KEY={SumoAccessKey}"),
		rulebuilder.NoMatch("false positive 4", "SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}"),
		rulebuilder.NoMatch("false positive 5", `sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`),
		rulebuilder.NoMatch("false positive 6", "SUMO_ACCESS_KEY: AbCeFG123"),
		rulebuilder.NoMatch("false positive 7", "sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;"),
	},
})
