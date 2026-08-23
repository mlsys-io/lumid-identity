package common

import "testing"

// ClassifyProvider drives the /code dashboard's provider grouping (Claude vs
// OpenRouter vs on-prem). It must agree with claude-proxy's
// isSelfHostedModel/isDeepseekFamily so the dashboard never labels a model as
// on-prem that the gate treats as metered, or vice versa.
func TestClassifyProvider(t *testing.T) {
	cases := []struct {
		model string
		want  LlmProvider
	}{
		{"claude-opus-5", ProviderClaude},
		{"claude-sonnet-5", ProviderClaude},
		{"claude-haiku-4-5-20251001", ProviderClaude},
		// Case-insensitive + context suffix stripped, matching the proxy.
		{"Claude-Opus-5", ProviderClaude},
		{"claude-sonnet-5[1m]", ProviderClaude},
		// On-prem self-hosted.
		{"deepseek-v4-flash", ProviderOnPrem},
		{"deepseek-v4-flash[1m]", ProviderOnPrem},
		// OpenRouter / metered pay-per-use.
		{"kimi-k3", ProviderOpenRouter},
		{"z-ai/glm-5.2", ProviderOpenRouter},
		{"deepseek/deepseek-v4-flash-0731", ProviderOpenRouter},
		{"some-future-model", ProviderOpenRouter},
		{"", ProviderOpenRouter},
	}
	for _, c := range cases {
		if got := ClassifyProvider(c.model); got != c.want {
			t.Errorf("ClassifyProvider(%q) = %v, want %v", c.model, got, c.want)
		}
	}
}
