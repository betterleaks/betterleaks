package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/v2/config"
)

var _ = Add(KubernetesSecret())

// KubernetesSecret validates if we detected a kubernetes secret which contains data!
func KubernetesSecret() config.Rule {
	// Only match basic variations of `kind: secret`, we don't want things like `kind: ExternalSecret`.
	//language=regexp
	kindPat := `\bkind:[ \t]*["']?\bsecret\b["']?`
	// Only matches values (`key: value`) under `data:` that are:
	// - valid base64 characters
	// - longer than 10 characters (no "YmFyCg==")
	//language=regexp
	dataPat := `\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))`
	r := config.Rule{
		ID:          "kubernetes-secret-yaml",
		Confidence:  "high",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		Regex: fmt.Sprintf(
			//language=regexp
			`(?i)(?:%s(?s:.){0,1000}?%s|%s(?s:.){0,1000}?%s)`, kindPat, dataPat, dataPat, kindPat),
		Keywords: []string{
			"secret",
		},
		// Kubernetes secrets are usually yaml files.
		Path:       `(?i)\.ya?ml$`,
		FilterExpr: "matchesAny(finding[\"secret\"], [`[\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:\\{\\{[ \\t\\w\"|$:=,.-]+}}|\"\"|'')`])\n|| matchesAny(finding[\"match\"], [`(kind:(?s:.)+\\n---\\n(?s:.)+\\bdata:|data:(?s:.)+\\n---\\n(?s:.)+\\bkind:)`])",
	}
	r.Tests = []config.RuleTest{
		{
			Name:       "true positive 1",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n\tcreationTimestamp: '2022-06-28T17:44:13Z'\n\tname: db-user-pass\n\tnamespace: default\ntype: Opaque\ndata:\n\t# the data is abbreviated in this example\n\tpassword: UyFCXCpkJHpEc2I9\n\tusername: YWRtaW4=\n",
			Attributes: map[string]string{"path": "after-comment.yml"},
			Expect: []config.ExpectedFinding{
				{Secret: "password: UyFCXCpkJHpEc2I9"},
			},
		},
		{
			Name:       `Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/ The "data"-key is after the identifier "kind: Secret"`,
			Input:      "apiVersion: v1\nkind: secret\ndata:\n\textra: YWRtaW46cGFzc3dvcmQ=\nmetadata:\n\tname: secret-sa-sample\n\tannotations:\n\t\tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "after-kubernetes.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "extra: YWRtaW46cGFzc3dvcmQ="},
			},
		},
		{
			Name:       "true positive 2",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ca-secret\ntype: Opaque\ndata:\n  ca.pem: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR4RENDQXF5Z0F3SUJBZ0lVV3pqUDl5RUk0eHlRSnBzVHVERU4yV2ROaUFzd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2FERUxNQWtHQTFVRUJoTUNWVk14RHpBTkJnTlZCQWdUQms5eVpXZHZiakVSTUE4R0ExVUVCeE1JVUc5eQpkR3hoYm1ReEV6QVJCZ05WQkFvVENrdDFZbVZ5Ym1WMFpYTXhDekFKQmdOVkJBc1RBa05CTVJNd0VRWURWUVFECkV3cExkV0psY201bGRHVnpNQjRYRFRFMk1EZ3hNVEUyTkRnd01Gb1hEVEl4TURneE1ERTJORGd3TUZvd2FERUwKTUFrR0ExVUVCaE1DVlZNeER6QU5CZ05WQkFnVEJrOXlaV2R2YmpFUk1BOEdBMVVFQnhNSVVHOXlkR3hoYm1ReApFekFSQmdOVkJBb1RDa3QxWW1WeWJtVjBaWE14Q3pBSkJnTlZCQXNUQWtOQk1STXdFUVlEVlFRREV3cExkV0psCmNtNWxkR1Z6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3QkhNOGN6anc0Q1cKK05wbklhV012RzZlcVhtelNZT20vbHdaNUhOMnVLck9xaTNHYUUyTjFKd2tzcGRmMXNOUGFZMHdPR2xkbURIZgoxSnlyTW8rUFdLVUVjWko1WGE4Vm02d2I0MlpjczN3MEp5dlEzWFJjaDQyMFJRWGRKayszcmMybWRvSVRkL0lmCnZjWms0N0RzQTMrQU5QSUlSTzdWRmZpS1JNRFpTUDR1OThnVjI2eW1zbjc0TzFVKzNVUHR1TEFTVTFLck9FTk4KR01FWG0ydTJpdmVvbTJrbjFlZTZuM1hCR1o2bU52cUNPdWUxRXdza0gvWkhoUVh1UDgyV1U5dVk0aGVORnoyQwpBNmR0Q0Q0c3Z6eHc3ZFQ2cVhsV0ZIWUYrc3VLVDhXNkczd3NkOWxzV0ZVY0ZWL0lwaTVobEVaTWprNFNoY3RqCjdpYnlrRURKM1FJREFRQUJvMll3WkRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFqQWRCZ05WSFE0RUZnUVVOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3SHdZRFZSMGpCQmd3Rm9BVQpOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUp1TUhYUms1TEVyCmxET1p4Mm9aRUNQZ29reXMzSGJsM05oempXd2pncXdxNVN6a011V3QrUnVkdnRTK0FUQjFtTjRjYTN0eSt2bWcKT09heTkvaDZoditmSE5jZHpYdWR5dFZYZW1KN3F4ZFoxd25DUUcwdnpqOWRZY0xFSGpJWi94dU1jNlY3dnJ4YwpSc0preGp5aE01UXBmRHd0eVZKeGpkUmVBZ0huSyswTkNieHdtQ3cyRGIvOXpudm9LWGk4TEQwbkQzOFQxY3R3CmhmdGxwTmRoZXFNRlpEZXBuTUYwY2g2cHo5TFV5Mkh1cnhrV2dkWVNjY2VNU0hPTzBMcG4xeVVBMWczOTJhUjUKWk81Zm5KMW95Vm1LVWFCeDJCMndsSVlUSXlES1ZiMnY1UXNHbnYvRHVTMDZhcmVLTmsvTGpHRTRlMXlHOHJkcwpacnZHMzNvUmtEbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n",
			Attributes: map[string]string{"path": "after-kubernetes.yml"},
			Expect: []config.ExpectedFinding{
				{Secret: "ca.pem: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR4RENDQXF5Z0F3SUJBZ0lVV3pqUDl5RUk0eHlRSnBzVHVERU4yV2ROaUFzd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2FERUxNQWtHQTFVRUJoTUNWVk14RHpBTkJnTlZCQWdUQms5eVpXZHZiakVSTUE4R0ExVUVCeE1JVUc5eQpkR3hoYm1ReEV6QVJCZ05WQkFvVENrdDFZbVZ5Ym1WMFpYTXhDekFKQmdOVkJBc1RBa05CTVJNd0VRWURWUVFECkV3cExkV0psY201bGRHVnpNQjRYRFRFMk1EZ3hNVEUyTkRnd01Gb1hEVEl4TURneE1ERTJORGd3TUZvd2FERUwKTUFrR0ExVUVCaE1DVlZNeER6QU5CZ05WQkFnVEJrOXlaV2R2YmpFUk1BOEdBMVVFQnhNSVVHOXlkR3hoYm1ReApFekFSQmdOVkJBb1RDa3QxWW1WeWJtVjBaWE14Q3pBSkJnTlZCQXNUQWtOQk1STXdFUVlEVlFRREV3cExkV0psCmNtNWxkR1Z6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3QkhNOGN6anc0Q1cKK05wbklhV012RzZlcVhtelNZT20vbHdaNUhOMnVLck9xaTNHYUUyTjFKd2tzcGRmMXNOUGFZMHdPR2xkbURIZgoxSnlyTW8rUFdLVUVjWko1WGE4Vm02d2I0MlpjczN3MEp5dlEzWFJjaDQyMFJRWGRKayszcmMybWRvSVRkL0lmCnZjWms0N0RzQTMrQU5QSUlSTzdWRmZpS1JNRFpTUDR1OThnVjI2eW1zbjc0TzFVKzNVUHR1TEFTVTFLck9FTk4KR01FWG0ydTJpdmVvbTJrbjFlZTZuM1hCR1o2bU52cUNPdWUxRXdza0gvWkhoUVh1UDgyV1U5dVk0aGVORnoyQwpBNmR0Q0Q0c3Z6eHc3ZFQ2cVhsV0ZIWUYrc3VLVDhXNkczd3NkOWxzV0ZVY0ZWL0lwaTVobEVaTWprNFNoY3RqCjdpYnlrRURKM1FJREFRQUJvMll3WkRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFqQWRCZ05WSFE0RUZnUVVOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3SHdZRFZSMGpCQmd3Rm9BVQpOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUp1TUhYUms1TEVyCmxET1p4Mm9aRUNQZ29reXMzSGJsM05oempXd2pncXdxNVN6a011V3QrUnVkdnRTK0FUQjFtTjRjYTN0eSt2bWcKT09heTkvaDZoditmSE5jZHpYdWR5dFZYZW1KN3F4ZFoxd25DUUcwdnpqOWRZY0xFSGpJWi94dU1jNlY3dnJ4YwpSc0preGp5aE01UXBmRHd0eVZKeGpkUmVBZ0huSyswTkNieHdtQ3cyRGIvOXpudm9LWGk4TEQwbkQzOFQxY3R3CmhmdGxwTmRoZXFNRlpEZXBuTUYwY2g2cHo5TFV5Mkh1cnhrV2dkWVNjY2VNU0hPTzBMcG4xeVVBMWczOTJhUjUKWk81Zm5KMW95Vm1LVWFCeDJCMndsSVlUSXlES1ZiMnY1UXNHbnYvRHVTMDZhcmVLTmsvTGpHRTRlMXlHOHJkcwpacnZHMzNvUmtEbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="},
			},
		},
		{
			Name:       "true positive 3",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\ndata:\n  .dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=",
			Attributes: map[string]string{"path": "after-multiline-folded.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: ".dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo="},
			},
		},
		{
			Name:       "true positive 4",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\ndata:\n  .dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=\n",
			Attributes: map[string]string{"path": "after-multiline-literal.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: ".dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo="},
			},
		},
		{
			Name:       "true positive 5",
			Input:      "apiVersion: 'v1'\nkind: 'Secret'\ndata:\n\tpassword: 'UyFCXCpkJHpEc2I9'\n\tusername: 'YWRtaW4='\nmetadata:\n\tname: 'db-user-pass'\n\tnamespace: 'default'\ntype: 'Opaque'",
			Attributes: map[string]string{"path": "after-quoted-1.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "password: 'UyFCXCpkJHpEc2I9'"},
			},
		},
		{
			Name:       "true positive 6",
			Input:      "apiVersion: \"v1\"\nkind: \"Secret\"\ndata:\n\tpassword: \"UyFCXCpkJHpEc2I9\"\n\tusername: \"YWRtaW4=\"\nmetadata:\n\tname: \"db-user-pass\"\n\tnamespace: \"default\"\ntype: \"Opaque\"",
			Attributes: map[string]string{"path": "after-quoted-2.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: `password: "UyFCXCpkJHpEc2I9"`},
			},
		},
		{
			Name:       "true positive 7",
			Input:      "apiVersion: v1\nkind: Secret\ntype: Opaque\nmetadata:\n  name: \"testk8smain-vault-secrets\"\n  labels:\n    app.k8s.veepee.tech/mutate: mutate\n  annotations:\n    argocd.argoproj.io/sync-wave: \"0\"\n    vault.security.banzaicloud.io/vault-role: \"corporate-sre_community_shared\"\ndata:\n  MINIO_ROOT_PASSWORD: dmF1bHQ6cHJvZHVjdHMvZGF0YS9pbnQvemF6ZXIvdGVzdGs4c21haW4vY29tbXVuaXR5L3NoYXJlZC9taW5pbyNNSU5JT19ST09UX1BBU1NXT1JE\n  MINIO_ROOT_USER: dmF1bHQ6cHJvZHVjdHMvZGF0YS9pbnQvemF6ZXIvdGVzdGs4c21haW4vY29tbXVuaXR5L3NoYXJlZC9taW5pbyNNSU5JT19ST09UX1VTRVI=",
			Attributes: map[string]string{"path": "annotations.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "MINIO_ROOT_PASSWORD: dmF1bHQ6cHJvZHVjdHMvZGF0YS9pbnQvemF6ZXIvdGVzdGs4c21haW4vY29tbXVuaXR5L3NoYXJlZC9taW5pbyNNSU5JT19ST09UX1BBU1NXT1JE"},
			},
		},
		{
			Name:       "true positive 8",
			Input:      "\napiVersion: v1\nkind: Secret\ndata:\n\tpassword: AAAAAAAAAAC7hjsA+H3owFygUv4w5B67lcSx14zff9FCPADiNbSwYWgE+O7Dhiy5tkRecs21ljjofvebe6xsYlA4cVmght0=",
			Attributes: map[string]string{"path": "base64-characters.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "password: AAAAAAAAAAC7hjsA+H3owFygUv4w5B67lcSx14zff9FCPADiNbSwYWgE+O7Dhiy5tkRecs21ljjofvebe6xsYlA4cVmght0="},
			},
		},
		{
			Name:       "true positive 9",
			Input:      "apiVersion: v1\ndata:\n\t# the data is abbreviated in this example\n\tpassword: UyFCXCpkJHpEc2I9\n\tusername: YWRtaW4=\nkind: Secret\nmetadata:\n\tcreationTimestamp: '2022-06-28T17:44:13Z'\n\tname: db-user-pass\n\tnamespace: default\ntype: Opaque",
			Attributes: map[string]string{"path": "before-comment.yml"},
			Expect: []config.ExpectedFinding{
				{Secret: "password: UyFCXCpkJHpEc2I9"},
			},
		},
		{
			Name:       `The "data"-key is before the identifier "kind: Secret"`,
			Input:      "apiVersion: v1\n data:\n \textra: YWRtaW46cGFzc3dvcmQ=\n kind: secret\n metadata:\n\t name: secret-sa-sample\n\t annotations:\n\t \tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "before-kubernetes.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "extra: YWRtaW46cGFzc3dvcmQ="},
			},
		},
		{
			Name:       "true positive 10",
			Input:      "apiVersion: v1\ndata:\n\tpassword: UyFCXCpkJHpEc2I9\n\tusername: YWRtaW4=\nkind: Secret\nmetadata:\n\tcreationTimestamp: '2022-06-28T17:44:13Z'\n\tname: db-user-pass\n\tnamespace: default\ntype: Opaque",
			Attributes: map[string]string{"path": "before-kubernetes.yml"},
			Expect: []config.ExpectedFinding{
				{Secret: "password: UyFCXCpkJHpEc2I9"},
			},
		},
		{
			Name:       "true positive 11",
			Input:      "apiVersion: v1\ndata:\n  .dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\nkind: Secret",
			Attributes: map[string]string{"path": "before-multiline-folded.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: ".dockercfg: >\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo="},
			},
		},
		{
			Name:       "true positive 12",
			Input:      "apiVersion: v1\ndata:\n  .dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=\nmetadata:\n  name: secret-dockercfg\ntype: kubernetes.io/dockercfg\nkind: Secret\n",
			Attributes: map[string]string{"path": "before-multiline-literal.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: ".dockercfg: |\n    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo="},
			},
		},
		{
			Name:       "true positive 13",
			Input:      "apiVersion: 'v1'\ndata:\n\textra: 'YWRtaW46cGFzc3dvcmQ='\nkind: 'Secret'\nmetadata:\n\tname: 'secret-sa-sample'\n\tannotations:\n\t\tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "before-quoted-1.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "extra: 'YWRtaW46cGFzc3dvcmQ='"},
			},
		},
		{
			Name:       "true positive 14",
			Input:      "apiVersion: \"v1\"\ndata:\n\textra: \"YWRtaW46cGFzc3dvcmQ=\"\nkind: \"secret\"\nmetadata:\n\tname: \"secret-sa-sample\"\n\tannotations:\n\t\tkubernetes.io/service-account.name: \"sa-name\"",
			Attributes: map[string]string{"path": "before-quoted-2.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: `extra: "YWRtaW46cGFzc3dvcmQ="`},
			},
		},
		{
			Name:       "true positive 15",
			Input:      "\napiVersion: v1\nkind: Secret\nmetadata:\n  name: heketi-secret\n  namespace: default\ndata:\n  # base64 encoded password. E.g.: echo -n \"mypassword\" | base64\n  key: bXlwYXNzd29yZA==",
			Attributes: map[string]string{"path": "comment.yaml"},
			Expect: []config.ExpectedFinding{
				{Secret: "key: bXlwYXNzd29yZA=="},
			},
		},
		{
			Name:       "false positive 1",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n  labels:\n    k8s-app: kubernetes-dashboard\n    addonmanager.kubernetes.io/mode: EnsureExists\n  name: kubernetes-dashboard-csrf\n  namespace: kubernetes-dashboard\ntype: Opaque\ndata:\n  csrf: \"\"\n",
			Attributes: map[string]string{"path": "after-empty-data.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 2",
			Input:      "apiVersion: 'kubernetes-client.io/v1'\nkind: ExternalSecret\nmetadata:\n  name: actions-exporter\n  namespace: github-actions-exporter\nspec:\n  backendType: secretsManager\n  data:\n    - key: MySecretManagerKey\n      name: github_token\n      property: github_token\n    - key: MySecretManagerKey",
			Attributes: map[string]string{"path": "after-externalsecret1.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 3",
			Input:      "apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: api-key\n  namespace: my-namespace\nspec:\n  secretStoreRef:\n    kind: ClusterSecretStore\n    name: aws-secretsmanager\n  refreshInterval: 1h\n  target:\n    creationPolicy: Owner\n  data:\n    - secretKey: api-key\n      remoteRef:\n        key: my-secrets-manager-secret",
			Attributes: map[string]string{"path": "after-externalsecret2.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       `The "data"-key is after the identifier "kind: Secret"`,
			Input:      "apiVersion: v1\nkind: secret\ndata:\n\textra: YmFyCg==\nmetadata:\n\tname: secret-sa-sample\n\tannotations:\n\t\tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "after-min-length.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 4",
			Input:      "apiVersion: isindir.github.com/v1alpha3\nkind: SopsSecret\nmetadata:\n  name: sopssecret-sample\nspec:\n  secretTemplates:\n    - name: my-secret-name-0\n      labels:\n        label0: value0\n        labelK: valueK\n      annotations:\n        key0: value0\n        keyN: valueN\n      stringData:\n        data-name0: data-value0\n        data-nameL: data-valueL\n    - name: my-secret-name-1\n      labels:\n        label1: value1\n      annotations:\n        key1: value1\n      data:\n        data-name1: ZGF0YS12YWx1ZTE=\n        data-nameM: ZGF0YS12YWx1ZU0=",
			Attributes: map[string]string{"path": "after-sopssecret.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 5",
			Input:      "apiVersion: 'kubernetes-client.io/v1'\nmetadata:\n  name: actions-exporter\n  namespace: github-actions-exporter\nspec:\n  backendType: secretsManager\n  data:\n    - key: MySecretManagerKey\n      name: github_token\n      property: github_token\nkind: ExternalSecret\n",
			Attributes: map[string]string{"path": "before-externalsecret1.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 6",
			Input:      "apiVersion: external-secrets.io/v1beta1\nspec:\n  secretStoreRef:\n    kind: ClusterSecretStore\n    name: aws-secretsmanager\n  refreshInterval: 1h\n  target:\n    creationPolicy: Owner\n  data:\n    - secretKey: api-key\n      remoteRef:\n        key: my-secrets-manager-secret\nmetadata:\n  name: api-key\n  namespace: my-namespace\nkind: ExternalSecret\n",
			Attributes: map[string]string{"path": "before-externalsecret2.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       `The "data"-key is before the identifier "kind: Secret" 2`,
			Input:      "apiVersion: v1\ndata:\n\textra: YmFyCg==\nkind: secret\nmetadata:\n\tname: secret-sa-sample\n\tannotations:\n\t\tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "before-min-length.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "https://github.com/isindir/sops-secrets-operator/blob/8aaf8bb368dc841a2d57f251bd839f08216a9328/config/samples/isindir_v1alpha3_sopssecret.yaml#L4",
			Input:      "apiVersion: isindir.github.com/v1alpha3\nspec:\n  secretTemplates:\n    - name: my-secret-name-1\n      labels:\n        label1: value1\n      annotations:\n        key1: value1\n      data:\n        data-name1: ZGF0YS12YWx1ZTE=\n        data-nameM: ZGF0YS12YWx1ZU0=\nkind: SopsSecret\nmetadata:\n  name: sopssecret-sample\n",
			Attributes: map[string]string{"path": "before-sopssecret.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 7",
			Input:      "apiVersion: v1\n data:\n \tpassword: {{ .Values.Password }}\n kind: secret\n metadata:\n \tname: secret-sa-sample\n \tannotations:\n \t\tkubernetes.io/service-account.name: 'sa-name'",
			Attributes: map[string]string{"path": "before-template.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 8",
			Input:      "apiVersion: v1            \nkind: Secret              \nmetadata:                 \n  name: registry-auth-data\ntype: Opaque              \ndata:                     \n  htpasswd: ''\n",
			Attributes: map[string]string{"path": "empty-quotes1.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 9",
			Input:      "apiVersion: v1            \nkind: Secret              \nmetadata:                 \n  name: registry-auth-data\ntype: Opaque              \ndata:                     \n  htpasswd: \"\"\n",
			Attributes: map[string]string{"path": "empty-quotes2.yml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 10",
			Input:      "apiVersion: v1            \nkind: Secret              \nmetadata:                 \n  name: registry-auth-data\ntype: Opaque              \ndata:                     \n  htpasswd: {{ htpasswd }}\n---                       \napiVersion: v1            \n                          kind: ReplicationController",
			Attributes: map[string]string{"path": "overly-permissive1.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 11",
			Input:      "apiVersion: v1\nkind: Secret\nmetadata:\n  labels:\n    k8s-app: kubernetes-dashboard\n    addonmanager.kubernetes.io/mode: EnsureExists\n  name: kubernetes-dashboard-csrf\n  namespace: kubernetes-dashboard\ntype: Opaque\ndata:\n  csrf: \"\"\n\n---\n\napiVersion: v1\nkind: Secret\nmetadata:\n  labels:\n    k8s-app: kubernetes-dashboard\n    addonmanager.kubernetes.io/mode: EnsureExists\n  name: kubernetes-dashboard-key-holder\n  namespace: kubernetes-dashboard\ntype: Opaque\n",
			Attributes: map[string]string{"path": "overly-permissive2.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 12",
			Input:      " kind: Secret\n target:\n   name: mysecret\n   creationPolicy: Owner\n\n---\n\nkind: ConfigMap\n data:\n       conversionStrategy: Default\n       decodingStrategy: None\n       key: secret/mysecret\n       property: foo\n     secretKey: foo",
			Attributes: map[string]string{"path": "overly-permissive3.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "https://github.com/luca-iachini/argocd-test/blob/af0c8eaba270bc918108c8bc3b909f26a4fe995d/kustomize/base/app1/secrets.enc.yaml#L4",
			Input:      "apiVersion: isindir.github.com/v1alpha3\nkind: SopsSecret\nmetadata:\n    name: app1-sopssecret\n    namespace: test\nspec:\n    suspend: false\n    secretTemplates:\n    -   name: ENC[AES256_GCM,data:W3PiZ6lD6bpfAdI=,iv:2qF98ZkchgfWF4tZo8fok6zY0ZLNRV3wFpl8n2iyC7I=,tag:FzoL+CZHkLEqfWKniRApBA==,type:str]\n        labels:\n            app: ENC[AES256_GCM,data:t9ujIQ==,iv:slZBpmKF+DOg/wVBWmq5iTqkRBZUMao0a3MdoxzJs3s=,tag:xJyhdJ4rn/cB/4mxHzmGig==,type:str]\n        stringData:\n            db-password: ENC[AES256_GCM,data:O+5l4g==,iv:c/dS4BCBMbnKsXYuzBuCuVQt8RV9bOv5HgdpL+iwmns=,tag:KkQfh6OymvCt4uC13p318g==,type:str]\nsops:\n    kms: []\n    gcp_kms: []\n    azure_kv: []\n    hc_vault: []\n    lastmodified: '2021-10-21T10:56:37Z'\n    mac: ENC[AES256_GCM,data:Tl1V1PuI5tZ0Hu3qxxzpDNeKQkuW0g/x/Mlp1yM6HaBqDr+r2FukLdYSYqjjJ3A8g+YkpvMib50M7j0V7zoX9sgCvMKEg86pRsWtThv8n/L+bsjClVTqnhJ9nfYlaPOMlvggbiMOE5hXPIuVz8WXYoVYJ2cVNCd/GfwOraUmj7I=,iv:n7HVI13okfbW3FS/ZsJ2GNmibudxc/TlkLa3umQQ+vc=,tag:R4ikep1wlxlDWlODJqFHHw==,type:str]\n    pgp:\n    -   created_at: '2021-10-21T10:56:37Z'\n        enc: |\n            -----BEGIN PGP MESSAGE-----\n\n            hQGMA3muqimBu2IIAQwAkhR19/6roLq06oaD12vqDMes3/8FweAHxa6TLKg+LRjp\n            2/ntiRJHPBP9DYYFZbkTo8lAmIdVF7KfGIqWgPm5JiNhqfVRhyGPCRgBE7+I8qH6\n            EML9Vo/76kJLHtIjs5rOg7OXgwwitaibs1q6uyVY8TuaGXYIOO1iwL9xVtbayIry\n            NMQd1tFcNb6Vb86Plqm+T1VnSOJMUvryxrLelx89UNM0ctepyVu6YY9jpBjV0QLJ\n            NqNkKAGIMv3RNa9bZHTwveo9T0oXtFnk5H33BxH0ky/DGpD+5Ch1YgbzbqVnr+Bm\n            RX0R/GRhS9IDInd+eiyVX6y3LR5di0fc8TuK43+96wTG+2+ck+lbMrkHYsL2UJNv\n            bAjlOWmIcL4UwGlEOj4EzwcEx+xP3dq57pJ+DasfNwVqps2Kk+ofodR7d6gx7ELH\n            UQmLypCtkRic9v8fVSA2vEL8hAlg9bT8tpHLhHMOwe228cL5dTzFD60RoP+ovRar\n            jIU59Pnu1bnM4pXWEVA20l4BzJ8Fd6gj3TfAg/7Mat+dnTaUwnPgRSybFn0ZZHMW\n            RJDBPkMGFfSGRDfLeD37d61mI31360/w/61LaVp1sdDYodBJCRZFA1YzbqZcxnDl\n            YRjRmpcVRnO+o72CnU/P\n            =V4l4\n            -----END PGP MESSAGE-----\n        fp: 73019E949C1D3C3D1BE8B718C7CD51A565AB592C\n    encrypted_suffix: Templates\n    version: 3.6.1",
			Attributes: map[string]string{"path": "sopssecret.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "https://github.com/gitleaks/gitleaks/issues/1644",
			Input:      "apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: example\n  namespace: example-ns\nspec:\n  refreshInterval: 15s\n  secretStoreRef:\n    name: example\n    kind: SecretStore\n  target:\n    name: mysecret\n    creationPolicy: Owner\n  data:\n    - remoteRef:\n        conversionStrategy: Default\n        decodingStrategy: None\n        key: secret/mysecret\n        property: foo\n      secretKey: foo\n",
			Attributes: map[string]string{"path": "wrong-kind.yaml"},
			Expect:     []config.ExpectedFinding{},
		},
	}
	return r
}
