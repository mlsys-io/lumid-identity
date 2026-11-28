package handler

import "testing"

func TestGPUDailyBudgetPerUserOverride(t *testing.T) {
	t.Setenv("MEASURE_GPU_DAILY_BUDGET", "12")
	t.Setenv("MEASURE_GPU_DAILY_BUDGET_USERS", "9731a2bb=24, short=99,bad=x, a3f48236-ffe9=40")
	cases := map[string]int{
		"9731a2bb-b5e4-489b-8ced-a7b1327b2079": 24, // 8-char prefix matches
		"a3f48236-ffe9-4fb9-9548-6e044d5cd9c7": 40,
		"shortxyz-0000":                        12, // keys under 8 chars never match
		"ffffffff-0000":                        12,
	}
	for sub, want := range cases {
		if got := gpuDailyBudget(sub); got != want {
			t.Errorf("gpuDailyBudget(%s) = %d, want %d", sub, got, want)
		}
	}
	t.Setenv("MEASURE_GPU_DAILY_BUDGET_USERS", "")
	if got := gpuDailyBudget("9731a2bb-x"); got != 12 {
		t.Errorf("no override: got %d", got)
	}
}
