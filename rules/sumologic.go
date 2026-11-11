package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "sumologic-access-id",
	Confidence:  "medium",
	Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
	Regex:       Assignment([]string{"(?-i:[Ss]umo|SUMO)"}, "(?i)(?-i:su)[a-zA-Z0-9]{12}"),
	Keywords: []string{
		"sumo",
	},
	FilterExpr: MinEntropyAndTokenEfficiency,
	Tests: []config.RuleTest{
		Match("sumo assignment", `sumoToken = "suRFbD56TI2smT"`, "suRFbD56TI2smT"),
		Match("true positive 1", `sumologic.accessId = "su9OL59biWiJu7"`, "su9OL59biWiJu7"),
		Match("true positive 2", `sumologic_access_id = "sug5XpdpaoxtOH"`, "sug5XpdpaoxtOH"),
		Match("true positive 3", `export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, "suDbJw97o9WVo0"),
		Match("true positive 4", `SUMO_ACCESS_ID = "suGyI5imvADdvU"`, "suGyI5imvADdvU"),
		NoMatch("false positive 1", "- (NSNumber *)sumOfProperty:(NSString *)property;"),
		NoMatch("false positive 2", "- (NSInteger)sumOfValuesInRange:(NSRange)range;"),
		NoMatch("false positive 3", "+ (unsigned char)byteChecksumOfData:(id)arg1;"),
		NoMatch("false positive 4", "sumOfExposures = sumOfExposures;"),
		NoMatch("false positive 5", ".si-sumologic.si--color::before { color: #000099; }"),
		NoMatch("false positive 6", "/// Based on the SumoLogic keyword syntax:"),
		NoMatch("false positive 7", `sumologic_access_id         = ""`),
		NoMatch("false positive 8", "SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}"),
		NoMatch("false positive 9", "export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX"),
		NoMatch("false positive 10", "sumObj = suGyI5imvADdvU"),
		NoMatch("false positive 11", `sumologic.accessId = "SU9OL59biWiJu7"`),
	},
})

var _ = Add(config.Rule{
	ID:          "sumologic-access-token",
	Confidence:  "medium",
	Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
	Regex:       Assignment([]string{"(?-i:[Ss]umo|SUMO)"}, `(?i)`+AlphaNumeric("64")),
	Keywords: []string{
		"sumo",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("sumo assignment", `sumoToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
		Match("true positive 1", `export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, "3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"),
		Match("true positive 2", "SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk", "gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk"),
		Match("true positive 3", "SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7", "9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7"),
		Match("true positive 4", `sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`, "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"),
		NoMatch("false positive 1", "#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		NoMatch("false positive 2", "-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`"),
		NoMatch("false positive 3", "SUMO_ACCESS_KEY={SumoAccessKey}"),
		NoMatch("false positive 4", "SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}"),
		NoMatch("false positive 5", `sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`),
		NoMatch("false positive 6", "SUMO_ACCESS_KEY: AbCeFG123"),
		NoMatch("false positive 7", "sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;"),
	},
})
