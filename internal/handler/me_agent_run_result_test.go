package handler

import "testing"

func TestSummarizeRunResultLiftsCommandOutput(t *testing.T) {
	res := map[string]any{
		"ok":     true,
		"action": "run_loop",
		"data": map[string]any{
			"engine":         "command",
			"command_engine": map[string]any{"ok": true, "outcome": "claimed", "claim_id": "c-123", "symbol": "KXBTCD-X"},
			"metrics":        map[string]any{"status": "claimed"},
		},
	}
	out := summarizeRunResult(map[string]any{"job_id": "j"}, res)
	ce, _ := out["output"].(map[string]any)
	if ce["claim_id"] != "c-123" || out["ok"] != true {
		t.Fatalf("claim_id not surfaced: %#v", out)
	}
	if out["metrics"] == nil {
		t.Fatalf("metrics dropped: %#v", out)
	}
}

func TestSummarizeRunResultCarriesError(t *testing.T) {
	out := summarizeRunResult(map[string]any{}, map[string]any{"ok": false, "error": "boom", "data": map[string]any{}})
	if out["error"] != "boom" || out["ok"] != false {
		t.Fatalf("error not carried: %#v", out)
	}
}

func TestRunResultRejectsMalformedID(t *testing.T) {
	out, ok := toolRunResult("u", "../etc")
	if ok || out["error"] == nil {
		t.Fatalf("malformed id accepted: %#v", out)
	}
}
