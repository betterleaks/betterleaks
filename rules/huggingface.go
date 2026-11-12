package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const huggingFaceValidateExpr = `let r = http.get("https://huggingface.co/api/whoami-v2", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid",
    "analysis": {
      "id": (r.json?.id ?? ""),
      "username": (r.json?.name ?? ""),
      "name": (r.json?.fullname ?? ""),
      "email": (r.json?.email ?? ""),
      "orgs": (r.json?.orgs ?? []),
      "auth": (r.json?.auth ?? {})
    }
  } : r.status == 401 && (r.body contains "expired") ? {
    "result": "revoked",
    "reason": "Token expired"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

// whoami-v2 returns token grants, including their resource scopes. Organization
// policies and the owner's access can restrict their use further. Membership
// alone does not establish fine-grained access.
// https://huggingface.co/.well-known/openapi.json
// https://huggingface.co/docs/hub/security-tokens
// Permission names: Hugging Face's FineGrainedToken/ViewUtils definitions.
// Inference invocation is not a data write, and configuring secrets does not
// establish the ability to read secret values.
const huggingFaceAnalyzeExpr = `let input = validation.analysis;
let auth = input["auth"] ?? {};
let access_token = auth["accessToken"] ?? {};
let role = access_token["role"] ?? "";
let orgs = input["orgs"] ?? [];
let fine_grained = role == "fineGrained" ? (access_token["fineGrained"] ?? {}) : {};
let global = fine_grained["global"] ?? [];
let scoped = fine_grained["scoped"] ?? [];
let permissions = sort(uniq(concat(global, flatten(map(scoped, {#.permissions ?? []})))));
let gated = fine_grained["canReadGatedRepos"] ?? false;
let capabilities = analysis.capabilities({
  "read": role in ["read", "write"] || gated || any(permissions, {# in [
    "repo.read", "repo.content.read", "repo.content.metadata.read", "repo.lfs.read",
    "repo.config.read", "repo.access.read", "collection.read", "org.read", "org.members.read",
    "user.billing.read", "user.notifications.read", "user.membership.read",
    "inference.endpoints.read", "job.read"
  ]}),
  "write": role == "write" || any(permissions, {# in [
    "repo.write", "repo.content.write", "repo.config.write", "repo.config.doi.write",
    "repo.config.visibility.write", "repo.config.variables.write", "repo.config.secrets.write",
    "repo.access.write", "discussion.write", "post.write", "collection.write",
    "inference.endpoints.write", "job.write"
  ]}),
  "manage_users": any(permissions, {# in ["org.write", "org.members.write"]})
});
{
  "reason": len(capabilities) > 0 ? "" : "Hugging Face returned no recognized permission grants",
  "metadata": role == "fineGrained" ? {
    "role": role,
    "token_name": access_token["displayName"] ?? "",
    "permissions": permissions
  } : (role == "" ? {} : {"role": role}),
  "identity": {
    "id": string(input["id"] ?? ""),
    "username": input["username"] ?? "",
    "name": input["name"] ?? "",
    "email": input["email"] ?? "",
    "account": role != "fineGrained" && len(orgs) == 1 ? {
      "id": string(orgs[0]?.id ?? ""),
      "name": orgs[0]?.name ?? ""
    } : {}
  },
  "capabilities": capabilities
}`

// The provider documents immediate, global invalidation of matching tokens on
// 202, while deliberately not disclosing whether the submitted token existed.
// https://huggingface.co/docs/hub/security-tokens#revoking-a-leaked-token
const huggingFaceRevokeExpr = `let r = http.post("https://huggingface.co/api/credentials/revoke", {
  "Content-Type": "application/json"
}, toJSON({"credentials": [finding["secret"]]}));
r.status == 202 ? {
  "result": "revoked",
  "reason": "Hugging Face invalidated any matching token; prior token validity is not disclosed"
} : revoke.unknown(r)`

// Reference: https://huggingface.co/docs/hub/security-tokens
//
// Old tokens have the prefix `api_`, however, I am not sure it's worth detecting them as that would be high noise.
// https://huggingface.co/docs/api-inference/quicktour
var _ = rulebuilder.Add(config.Rule{
	ID:          "huggingface-access-token",
	Confidence:  "high",
	Description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
	Regex:       rulebuilder.Token("hf_(?i:[a-z]{34})"),
	Keywords: []string{
		"hf_",
	},
	ValidateExpr: huggingFaceValidateExpr,
	AnalyzeExpr:  huggingFaceAnalyzeExpr,
	RevokeExpr:   huggingFaceRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `huggingfaceToken = "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"`, "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"),
		rulebuilder.Match("true positive 1", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 2", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 3", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 4", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 5", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 6", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 7", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 8", "huggingface-cli login --token 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", "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"),
		rulebuilder.Match("true positive 9", `-H "Authorization: Bearer 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"`, "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"),
		rulebuilder.Match("true positive 10", "DEV=1 HF_TOKEN=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 poetry run python app.py", "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"),
		rulebuilder.Match("true positive 11", "use_auth_token='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')", "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"),
		rulebuilder.Match("true positive 12", `CI_HUB_USER_TOKEN = "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"`, "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"),
		rulebuilder.Match("true positive 13", `- Change line 5 and add your Hugging Face token, that is, instead of 'hf_token = "ADD_YOUR_HUGGING_FACE_TOKEN_HERE"', you will need to change it to something like'hf_token = "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"'`, "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"),
		rulebuilder.Match("true positive 14", "# Not critical, only usable on the sandboxed CI instance.\n\t\tTOKEN = \"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\"", "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"),
		rulebuilder.Match("true positive 15", `    parser.add_argument("--hf_token", type=str, default='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', help="Hugging Face Access Token to access PyAnnote gated models")`, "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"),
		rulebuilder.NoMatch("false positive 1", "- (id)hf_requiredCharacteristicTypesForDisplayMetadata;"),
		rulebuilder.NoMatch("false positive 2", `amazon.de#@#div[data-cel-widget="desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2ClickPagination"]`),
		rulebuilder.NoMatch("false positive 3", "                            _kHMSymptomhf_generatedByHomeAppForDebuggingPurposesKey,"),
		rulebuilder.NoMatch("false positive 4", "    #define OSCHF_DebugGetExpectedAverageCrystalAmplitude NOROM_OSCHF_DebugGetExpectedAverageCrystalAmplitude"),
		rulebuilder.NoMatch("false positive 5", "  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),"),
		rulebuilder.NoMatch("false positive 6", "+HWI-ST565_0092:4:1101:5508:5860#ACTTGA/1\n\t\tbb_eeeeegfgffhiiiiiiiiiiihiiiiicgafhf_eefghihhiiiifhifhhdhifhiiiihifdgdhggf\\bbceceedbcd\n\t\t@HWI-ST565_0092:4:1101:7621:5770#ACTTGA/1"),
		rulebuilder.NoMatch("false positive 7", "y{}x|~|}\x7f\x7f{~}}~|\x7f\x7f~}||�~|�\x7f{��|\x7f\x7f{}\x7f{|~z{}{{|{||{|}|{}{~|y}vjoePbUBJ7&;\"\x1a;  <\x1f\x1f;\x1f :\x1f\x1f;\x1f\x1e?!!;\x1e\x1e<\x1f\x1f7%$IACa_ecghbfbaebejhahfbhf_ddbficghbgfbhhcghdghfhigiifhhehhdggcgfchf_fgcei^[[.40&54\"56\x1f66 6"),
		rulebuilder.NoMatch("false positive 8", "                    change_dir(cwd)\n\t\tsubdirs = glob.glob('HF_CAASIMULIAComputeServicesBuildTime.HF*.Linux64')\n\t\tif len(subdirs) == 1:"),
		rulebuilder.NoMatch("false positive 9", "        os.environ.get(\"HF_AUTH_TOKEN\",\n\t\t\"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"),"),
		rulebuilder.NoMatch("false positive 10", "# HuggingFace API Token https://huggingface.co/settings/tokens\n\t\tHUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,"),
	},
})

// Will be deprecated Aug 1st, 2023.
var _ = rulebuilder.Add(config.Rule{
	ID:          "huggingface-organization-api-token",
	Confidence:  "high",
	Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
	Regex:       rulebuilder.Token("api_org_(?i:[a-z]{34})"),
	Keywords: []string{
		"api_org_",
	},
	ValidateExpr: huggingFaceValidateExpr,
	AnalyzeExpr:  huggingFaceAnalyzeExpr,
	RevokeExpr:   huggingFaceRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `huggingfaceToken = "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"`, "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"),
		rulebuilder.Match("bare secret", "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", "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"),
		rulebuilder.Match("true positive 1", "`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`", "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"),
		rulebuilder.Match("true positive 2", `\'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'\`, "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"),
		rulebuilder.Match("true positive 3", "def test_private_space(self):\n        hf_token = \"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\"  # Intentionally revealing this key for testing purposes\n        io = gr.load(", "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"),
		rulebuilder.Match("true positive 4", `hf_token = "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"  # Intentionally revealing this key for testing purposes`, "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"),
		rulebuilder.Match("true positive 5", `"news_train_dataset = datasets.load_dataset('nlpHakdang/aihub-news30k',  data_files = \"train_news_text.csv\", use_auth_token='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')\n",`, "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"),
		rulebuilder.Match("true positive 6", "os.environ['HUGGINGFACEHUB_API_TOKEN'] = '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'", "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"),
		rulebuilder.Match("bare secret 2", "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", "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"),
		rulebuilder.NoMatch("false positive 1", `public static final String API_ORG_EXIST = "APIOrganizationExist";`),
		rulebuilder.NoMatch("false positive 2", "const api_org_controller = require('../../controllers/api/index').organizations;"),
		rulebuilder.NoMatch("false positive 3", `API_ORG_CREATE("https://qyapi.weixin.qq.com/cgi-bin/department/create?access_token=ACCESS_TOKEN"),`),
		rulebuilder.NoMatch("false positive 4", "def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):\n\t\tmonkeypatch.setattr(\"requests.sessions.Session.request\", called_with)"),
		rulebuilder.NoMatch("false positive 5", "    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):\n        body = self.fixtures.load(\"api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a.xml\")\n        return httplib.OK, body, headers, httplib.responses[httplib.OK]"),
		rulebuilder.NoMatch("false positive 6", "<p>You should see a token <code>hf_xxxxx</code> (old tokens are <code>api_XXXXXXXX</code> or <code>api_org_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</code>).</p>"),
		rulebuilder.NoMatch("false positive 7", "  From Hugging Face docs:\n\t\tYou should see a token hf_xxxxx (old tokens are api_XXXXXXXX or api_org_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).\n\t\tIf you do not submit your API token when sending requests to the API, you will not be able to run inference on your private models."),
	},
})
