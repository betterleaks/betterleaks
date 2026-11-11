package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "onesignal-rich-authentication-token",
	Confidence:  "high",
	Description: "OneSignal rich authentication token.",
	Regex:       Token(`os_v2_(?:app|org)_[a-z2-7]{103}`),
	Keywords:    []string{"os_v2_app_", "os_v2_org_"},
	ValidateExpr: `let r = http.get("https://api.onesignal.com/apps", {
    "Authorization": "Key " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 || (r.status == 403 && len(r.json?.errors ?? []) > 0) ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "ONESIGNAL_API_KEY=os_v2_app_3jbv3atgc6aj4lsufp74jucmzfjsqrpsvj7gdrxmhme5lny6ztpdprclcubf5yxwe6d4z4fceqbadbwozt3xdfdn5mys4n6bs5hy3bv", "os_v2_app_3jbv3atgc6aj4lsufp74jucmzfjsqrpsvj7gdrxmhme5lny6ztpdprclcubf5yxwe6d4z4fceqbadbwozt3xdfdn5mys4n6bs5hy3bv"),
		Match("true positive 2", "ONESIGNAL_ORG_API_KEY=os_v2_org_3jbv3atgc6aj4lsufp74jucmzfjsqrpsvj7gdrxmhme5lny6ztpdprclcubf5yxwe6d4z4fceqbadbwozt3xdfdn5mys4n6bs5hy3bv", "os_v2_org_3jbv3atgc6aj4lsufp74jucmzfjsqrpsvj7gdrxmhme5lny6ztpdprclcubf5yxwe6d4z4fceqbadbwozt3xdfdn5mys4n6bs5hy3bv"),
		NoMatch("false positive 1", "ONESIGNAL_APP_ID=202d4f61-1ca9-42df-9d36-bb17d8123abc"),
		NoMatch("false positive 2", "ONESIGNAL_API_KEY=os_v2_app_short"),
	},
})
