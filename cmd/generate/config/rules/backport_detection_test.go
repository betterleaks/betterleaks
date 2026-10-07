package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
)

func TestBackportedDetection(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	detector := detect.NewDetector(cfg)
	const cloudflareToken = "cfat_Ab3dEf7hIj9lMn2pQr4tUv6xYz8bCd0fGh1jKl5n0123abcd"
	const tableauToken = "/MqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv"
	const tableauContext = "TABLEAU_TOKEN_NAME=production_service\nTABLEAU_SERVER=https://prod.online.tableau.com\nTABLEAU_PAT_SECRET="
	for _, tc := range []struct {
		name, input, id, secret string
		components              int
	}{
		{"NuGet CLI", "dotnet nuget push package.nupkg --api-key oy2ds22slm75wwyowxgaerhyx5siaqoubbwo3om37cjnby", "nuget-api-key", "oy2ds22slm75wwyowxgaerhyx5siaqoubbwo3om37cjnby", 0},
		{"NuGet uppercase", "NUGET_API_KEY=OY2IZT6YMOZVUKMFCARAHVG4ADT4ZGG6HO5I3KQU4WSTCE", "nuget-api-key", "OY2IZT6YMOZVUKMFCARAHVG4ADT4ZGG6HO5I3KQU4WSTCE", 0},
		{"NuGet invalid fixed bits", "NUGET_API_KEY=oy2zzbtp73dk4lcfuyuargeoefaqwmbu7pcpy7aznmzeiy", "nuget-api-key", "", 0},
		{"Cloudflare account component", "CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111\nCLOUDFLARE_API_TOKEN=" + cloudflareToken, "cloudflare-api-key.2", cloudflareToken, 1},
		{"Cloudflare missing optional component", cloudflareToken, "cloudflare-api-key.2", cloudflareToken, 0},
		{"Cloudflare component outside window", "CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111" + strings.Repeat("\n", 7) + cloudflareToken, "cloudflare-api-key.2", cloudflareToken, 0},
		{"Cloudflare user token", strings.Replace(cloudflareToken, "cfat_", "cfut_", 1), "cloudflare-api-key.2", strings.Replace(cloudflareToken, "cfat_", "cfut_", 1), 0},
		{"Cloudflare legacy ID", `cloudflare_api_key="Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, "cloudflare-api-key", "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4", 0},
		{"Cloudflare account ID hidden", "CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111", "cloudflare-account-id.1", "", 0},
		{"Tableau slash boundary", tableauContext + tableauToken, "tableau-personal-access-token.1", tableauToken, 2},
		{"Tableau plus boundary", tableauContext + strings.Replace(tableauToken, "/", "+", 1), "tableau-personal-access-token.1", strings.Replace(tableauToken, "/", "+", 1), 2},
		{"Tableau longer token", tableauContext + "A" + tableauToken, "tableau-personal-access-token.1", "", 0},
		{"Box client secret", `BOX_CLIENT_SECRET="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`, "box-api-access-token", "", 0},
		{"Box client prefix", `client_box_access_token="A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"`, "box-api-access-token", "", 0},
		{"Box neighboring client identifier", `client_id="example"; box_access_token="A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"`, "box-api-access-token", "A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			for _, finding := range detector.DetectString(tc.input) {
				if finding.RuleID != tc.id {
					continue
				}
				count++
				require.Equal(t, tc.secret, finding.Secret)
				if tc.components == 0 {
					require.Empty(t, finding.ComponentSets)
				} else {
					require.Len(t, finding.ComponentSets, 1)
					require.Len(t, finding.ComponentSets[0].Components, tc.components)
				}
			}
			if tc.secret == "" {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
		})
	}
}

func TestBackportedEntropyFiltersInDefaultConfig(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	for _, id := range []string{"elastic-cloud-api-key", "exoscale-api-key", "exoscale-api-secret", "scaleway-secret-key", "upcloud-api-token"} {
		t.Run(id, func(t *testing.T) {
			rule := cfg.Rules[id]
			require.NotEmpty(t, rule.Filter)
			program, err := runtime.CompileFilter(rule.Filter, nil)
			require.NoError(t, err)
			for _, tc := range []struct {
				secret string
				skip   bool
			}{
				{strings.Repeat("a", 60), true},
				{"Ab3dEf7hIj9lMn2pQr4tUv6xYz8bCd0fGh1jKl5n", false},
			} {
				skip, err := runtime.EvalFilter(program, map[string]any{"secret": tc.secret}, nil)
				require.NoError(t, err)
				require.Equal(t, tc.skip, skip)
			}
		})
	}
}
