package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/v2/config"
)

// https://curl.se/docs/manpage.html#-u
var _ = Add(config.Rule{
	ID:          "curl-auth-user",
	Confidence:  "high",
	Description: "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.",
	Regex:       `\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z)`,
	Keywords:    []string{"curl"},
	FilterExpr:  "entropy(finding[\"secret\"]) <= 2.0\n|| matchesAny(finding[\"secret\"], [\n  `[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)`,\n  `['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?`,\n  `[^:]+:\\[[^]]+]`,\n  `['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['\"]?`,\n  `['\"]?\\$\\{(?:[^{}]|\\{[^}]*\\})*\\}['\"]?:['\"]?\\$\\{(?:[^{}]|\\{[^}]*\\})*\\}['\"]?`,\n  `\\$\\([^)]+\\):\\$\\([^)]+\\)`,\n  `['\"]?\\$?{{[^}]+}}['\"]?:['\"]?\\$?{{[^}]+}}['\"]?`\n])",
	Tests: []config.RuleTest{
		Match("same lines, no quotes", "curl --cacert ca.crt -u elastic:P@ssw0rd$1 https://localhost:9200", "elastic:P@ssw0rd$1"),
		Match("different line", "sh-5.0$ curl -k -X POST https://infinispan:11222/rest/v2/caches/default/hello \\\n  -H 'Content-type: text/plain' \\\n  -d 'world' \\\n  -u developer:yqDVtkqPECriaLRi", "developer:yqDVtkqPECriaLRi"),
		Match("empty username", `curl -u ":d2LkV78zLx!t" https://localhost:9200`, `":d2LkV78zLx!t"`),
		Match("empty password", `curl -u "d2LkV78zLx!t:" https://localhost:9200`, `"d2LkV78zLx!t:"`),
		Match("long", "curl -sw '%{http_code}' -X POST --user  'johns:h0pk1ns~21s' $GItHUB_API_URL/$GIT_COMMIT --data", "'johns:h0pk1ns~21s'"),
		Match("same line, no quotes", "curl --user roger23@gmail.com:pQ9wTxu4Fg https://www.dropbox.com/cli_link?host_id=abcdefg -v", "roger23@gmail.com:pQ9wTxu4Fg"),
		Match("same line, single quotes", "curl -s --user 'api:d2LkV78zLx!t' \\\n    https://api.mailgun.net/v2/sandbox91d3515882ecfaa1c65be642.mailgun.org/messages", "'api:d2LkV78zLx!t'"),
		Match("same line, double quotes", `curl -s -v --user "j.smith:dB2yF6@qL9vZm1P#4J" "https://api.contoso.org/user/me"`, `"j.smith:dB2yF6@qL9vZm1P#4J"`),
		Match("true positive 1", `curl -X POST --user "{acd3c08b-74e8-4f44-a2d0-80694le24f46}":"{ZqL5kVrX1n8tA2}" --header "Accept: application/json" --data "{\"text\":\"Hello, world\",\"source\":\"en\",\"target\":\"es\"}" https://gateway.watsonplatform.net/language-translator/api`, `"{acd3c08b-74e8-4f44-a2d0-80694le24f46}":"{ZqL5kVrX1n8tA2}"`),
		Match("same line, mixed quoting", `curl --user kevin:'pRf7vG2h1L8nQkW9' -iX PATCH -H "Content-Type: application/json" -d`, "kevin:'pRf7vG2h1L8nQkW9'"),
		Match("different line 2", "$ curl https://api.dropbox.com/oauth2/token \\\n  --user c28wlsosanujy2z:qgsnai0xokrw4j1 --data grant_type=authorization_code", "c28wlsosanujy2z:qgsnai0xokrw4j1"),
		NoMatch("short", "curl -i -u 'test:test'"),
		NoMatch("environment variable", `   curl -sL --user "$1:$2" "$3" > "$4"`),
		NoMatch("placeholder", "curl -u <user:password> https://test.com/endpoint"),
		NoMatch("placeholder 2", "curl --user neo4j:[PASSWORD] http://[IP]:7474/db/data/"),
		NoMatch("no password", `curl -u "myusername" http://localhost:15130/api/check_user/`),
		NoMatch("false positive 1", "curl -u username:token"),
		NoMatch("false positive 2", `curl -u "${_username}:${_password}"`),
		NoMatch("false positive 3", `curl -u "${username}":"${password}"`),
		NoMatch("nested bash expansion", `curl -u "${USER:-${DEFAULT_USER}}:${APIKEY:-${DEFAULT_APIKEY}}"`),
		NoMatch("false positive 4", `curl -k -X POST -I -u "SRVC_JENKINS:${APPID}"`),
		NoMatch("empty username and password", `curl -u ":" https://localhost:9200`),
		NoMatch("long 2", "curl -sw '%{http_code}' -X POST --user '$USERNAME:$PASSWORD' $GItHUB_API_URL/$GIT_COMMIT --data"),
		NoMatch("false positive 5", `curl --user "xxx:yyy"`),
		NoMatch("environment variable 2", `           curl -sL --user "$GITHUB_USERNAME:$GITHUB_PASSWORD" "$GITHUB_URL" > "$TESTS_PATH"`),
		NoMatch("variable interpolation", `curl --silent --fail {{- if and $.Values.username $.Values.password }} --user "{{ $.Values.username }}:{{ $.Values.password }}"`),
		NoMatch("false positive 6", `curl -XGET -i -u "${{ env.ELK_ID }}:${{ build.env.ELK_PASS }}"`),
		NoMatch("false positive 7", `curl -XGET -i -u "${{needs.vault.outputs.account_id}}:${{needs.vault.outputs.account_password}}"`),
		NoMatch("false positive 8", `curl -XGET -i -u "${{ steps.vault.outputs.account_id }}:${{ steps.vault.outputs.account_password }}"`),
		NoMatch("command", `curl -X POST --user "$(cat ./login.txt):$(cat ./password.txt)"`),
		NoMatch("placeholder 3", "curl http://127.0.0.1:5000/file --user user:pass --digest        # digest auth"),
		NoMatch("placeholder 4", `   curl -X GET --insecure --user "username:password" \`),
		NoMatch("placeholder 5", `curl --silent --insecure --user ${f5user}:${f5pass} \`),
		NoMatch("no password 2", `curl --insecure --ssl-reqd "smtps://smtp.gmail.com" --mail-from "src@gmail.com" --mail-rcpt "dst@gmail.com" --user "src@gmail.com" --upload-file out.txt`),
		NoMatch("different command", "#HTTP command line test\ncurl -X POST -H \"Content-Type: application/json\" -d '{\"id\":12345,\"geo\":{\"latitude\":28.50,\"longitude\":-81.14}}' http://<ip>:8080/serve\n\n#UDP command line test\necho -n '{\"type\":\"serve\",\"channel\":\"/\",\"data\":{\"site_id\":8,\"post_id\":12345,\"geo\":{\"lat\":28.50,\"long\":-81.14}}}' >/dev/udp/127.0.0.1/41234\n\n#UDP Listener (for confirmation)\nnc -u -l 41234"),
	},
})

var _ = Add(CurlHeaderAuth())

// https://curl.se/docs/manpage.html#-H
func CurlHeaderAuth() config.Rule {
	// language=regexp
	authPat := `(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))`
	r := config.Rule{
		ID:          "curl-auth-header",
		Confidence:  "high",
		Description: "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.",
		Regex:       fmt.Sprintf(`\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"%s"|'%s')(?:\B|\s|\z)`, authPat, authPat),
		Keywords:    []string{"curl"},
		FilterExpr:  `entropy(finding["secret"]) <= 2.75`,
	}
	r.Tests = []config.RuleTest{
		Match("true positive 1", "curl --header  'Authorization:  5eb4223e-5008-46e5-be67-c7b8f2732305'", "5eb4223e-5008-46e5-be67-c7b8f2732305"),
		Match("same line, single quotes", `curl -H 'Authorization: Basic YnJvd3Nlcjo=' \`, "YnJvd3Nlcjo="),
		Match("same line, double quotes", `curl -k -X POST --header "Authorization: Basic djJlNEpYa0NJUHZ5a2FWT0VRXzRqZmZUdDkwYTp2emNBZGFzZWpmlWZiUDc2VUJjNDNNVDExclVh" "https://api-qa.example.com:8243/token" -d "grant_type=client_credentials"`, "djJlNEpYa0NJUHZ5a2FWT0VRXzRqZmZUdDkwYTp2emNBZGFzZWpmlWZiUDc2VUJjNDNNVDExclVh"),
		Match("different line, double quotes", "curl -X POST -H \"Content-Type: application/json\" \\\n -H \"Authorization: Basic MzUzYjMwMmM0NDU3NGY1NjUwNDU2ODdlNTM0ZTdkNmE6Mjg2OTI0Njk3ZTYxNWE2NzJhNjQ2YTQ5MzU0NTY0NmM=\" \\\n  -d '{\"user\":{\"emailAddress\":\"test@example.com\"}, \"password\":\"password\"}' \\\n  'http://localhost:8080/oauth2-provider/v1.0/users'", "MzUzYjMwMmM0NDU3NGY1NjUwNDU2ODdlNTM0ZTdkNmE6Mjg2OTI0Njk3ZTYxNWE2NzJhNjQ2YTQ5MzU0NTY0NmM="),
		Match("different line, single quotes", "#curl -X POST \\\n#  https://api.mailgun.net/v3/sandbox7dbcabccd4314c123e8b23599d35f5b6.mailgun.org/messages \\\n#  -H 'Authorization: Basic YXBpOmtleS1hN2MzNDJ3MzNhNWQxLTU2M2U3MjlwLTZhYjI3YzYzNzM0Ng==' \\\n#  -F from='Excited User <mailgun@sandbox7dbc123bccd4314c0aae8b23599d35f5b6.mailgun.org>' \\\n#  -F to='joe@example.com' \\\n#  -F subject='Hello' \\\n#  -F text='Testing some Mailgun awesomness!'", "YXBpOmtleS1hN2MzNDJ3MzNhNWQxLTU2M2U3MjlwLTZhYjI3YzYzNzM0Ng=="),
		Match("same line, double quotes 2", `# curl -X GET "http://localhost:3000/api/cron/status" -H "Authorization: Bearer cfcabd11c7ed9a41b1a3e063c32d5114"`, "cfcabd11c7ed9a41b1a3e063c32d5114"),
		Match("same line, single quotes 2", `curl -X PUT -H 'Authorization: Bearer jC+6TUUjCNHcVtAXpcqBCgxnA8r+qD6MatnYaf/+289y7HWpK0BWPyLHv/K4DMN32fufwmeVVjlo8zjgBh8kx3GfS6IqO70w1DVMSCTwX7fhEpiXaxzv0mhSMHDX9Kw63Q6DkavUWUV+MDNhCF5wGQrcdQNncVRF3YkuDHDT/xw2YWyZ/DX8k+gAYiC8gcD8Ueg0ljBVS1IDwPjuGoFPESJVxYr0MDPF2D8Pn2S5rq692U4D9ZLuluS46VA4DK6ig5P7QM5XVXi4V7vXM8qpN/zqneyz+w4PUh6NIX7QG6JczMhYd9maWRWVat5jDdyII63P6sNAy9QZjw+ClW211Q==' -d 'user={"account":"user@domain.com", "roles":["user"]}' http://127.0.0.1:8443/desks/1/occupy`, "jC+6TUUjCNHcVtAXpcqBCgxnA8r+qD6MatnYaf/+289y7HWpK0BWPyLHv/K4DMN32fufwmeVVjlo8zjgBh8kx3GfS6IqO70w1DVMSCTwX7fhEpiXaxzv0mhSMHDX9Kw63Q6DkavUWUV+MDNhCF5wGQrcdQNncVRF3YkuDHDT/xw2YWyZ/DX8k+gAYiC8gcD8Ueg0ljBVS1IDwPjuGoFPESJVxYr0MDPF2D8Pn2S5rq692U4D9ZLuluS46VA4DK6ig5P7QM5XVXi4V7vXM8qpN/zqneyz+w4PUh6NIX7QG6JczMhYd9maWRWVat5jDdyII63P6sNAy9QZjw+ClW211Q=="),
		Match("different line, double quotes 2", "curl https://api.openai.com/v1/chat/completions \\\n  -H \"Content-Type: application/json\" \\\n  -H \"Authorization: Bearer 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\" \\", "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"),
		Match("true positive 2", "curl -X GET \"https://api.cloudflare.com/client/v4/user/tokens/verify\" \\\n     -H \"Authorization: Bearer _FXNljbSRYMWx3TWrd7lgKhLtVZX6iskC8Wcbb4b\" \\\n     -H \"Content-Type:application/json\"", "_FXNljbSRYMWx3TWrd7lgKhLtVZX6iskC8Wcbb4b"),
		Match("true positive 3", `curl -H "Authorization: Bearer sha256~bRLFnzd59Z3XpZH5_seJPHALOuvbWiKwbFKSsoALkgp"`, "sha256~bRLFnzd59Z3XpZH5_seJPHALOuvbWiKwbFKSsoALkgp"),
		Match("token", `curl -H "Authorization: Api-Token 22cb987851bc5659l29114c62e60c79abd0d2c08" --request PUT https://appsecclass.report/api/use/635`, "22cb987851bc5659l29114c62e60c79abd0d2c08"),
		Match("token 2", `curl -H "Authorization: Token 22cb987851bc5659229114c62e60c79abd0d2c08" --request PUT https://appsecclass.report/api/use/635`, "22cb987851bc5659229114c62e60c79abd0d2c08"),
		Match("no prefix", `curl -L -H "Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25maWRlbmNlIjowLjh9.kvRPfjAhLhtRTczoRgctVGp7KY1QVH3UBZM-gM0x8ec" service1.local -> correct jwt `, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25maWRlbmNlIjowLjh9.kvRPfjAhLhtRTczoRgctVGp7KY1QVH3UBZM-gM0x8ec"),
		Match("no prefix 2", `curl -L -H "Authorization: sha256~bRLFnzd5@=-.a+/hgdS"`, "sha256~bRLFnzd5@=-.a+/hgdS"),
		Match("apikey", "curl -X GET \\\n     -H \"apikey: c4ed6c21-9dd5-4a05-8e3f-c56d1151cce8\" \\\n     -H \"Accept: application/json\" \\", "c4ed6c21-9dd5-4a05-8e3f-c56d1151cce8"),
		Match("api-token", `curl -X POST --header "Api-Token: Sk94HG7f6KB"`, "Sk94HG7f6KB"),
		Match("token 3", `curl -XPOST http://localhost:8080/api/tasks -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -H "Token: 3fea6af1349166ea" -d "content=hello-curl"`, "3fea6af1349166ea"),
		Match("X-$thing-ApiKey", "curl -X GET https://octopus.corp.net/\n     -H \"X-Octopus-ApiKey: 3a16750d-d363-41a4-8ebd-035408f7730f\" \\", "3a16750d-d363-41a4-8ebd-035408f7730f"),
		NoMatch("Placeholders", `curl https://example.com/micropub -d h=entry -d "content=Hello World" -H "Authorization: Bearer XXXXXXXXXXXX"`),
		NoMatch("false positive 1", `curl -X POST https://accounts.spotify.com/api/token -d grant_type=client_credentials --header "Authorization: Basic ..."`),
		NoMatch("false positive 2", "curl \\\n  -H \"Authorization: Bearer <Openverse API token>\" \\\n  \"https://api.openverse.org/v1/audio/?q=test\""),
		NoMatch("false positive 3", "curl -v -v -v -X POST https://domain/api/v1/authentication/sso/login-url/ \\\n  -H 'Content-Type: application/json' \\\n  -H \"Authorization: Token **********\" \\\n  -d '{\"username\": \"test\", \"next\": \"/luna/\"}'"),
		NoMatch("same line, invalid base64", `curl -XPOST http://localhost:8080/api/token -H "Authorization: basic {base64(email:password[\n])}" => token`),
		NoMatch("API Key placeholder", "curl -X GET \\\n     -H \"apikey: $API_KEY\" \\\n     -H \"Accept: $FORMAT\" \\\n\"$API_URL/rest/v1/stats_derniere_labellisation\""),
		NoMatch("different line, placeholder", "$ curl -X POST \"http://localhost:8000/v1/chat/completions\" \\\n    -H \"Content-Type: application/json\" \\\n    -H \"Authorization: Bearer $API_KEY\" \\\n    -d '{\n        \"model\": \"chatglm3-6b-32k\",\n        \"messages\": [{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"Hello!\"}]\n    }'"),
		NoMatch("script", `curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $(gcloud auth print-access-token)" https://workflowexecutions.googleapis.com/v1/projects/244283331594/locations/us-central1/workflows/sample-workflow/executions/43c925aa-514a-44c1-a0a4-a9f8f26fd2cb/callbacks/1705791f-d446-4e92-a6d0-a13622422e80_31864a51-8c13-4b03-ad4d-945cdc8d0631`),
		NoMatch("Not valid BASIC", `curl -X POST -H "Content-Type: application/json" -H "Authorization: Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25maWRlbmNlIjowLjh9.kvRPfjAhLhtRTczoRgctVGp7KY1QVH3UBZM-gM0x8ec" \`),
	}
	return r
}
