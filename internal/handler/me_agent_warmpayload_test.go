package handler

import (
	"encoding/json"
	"os"
	"testing"
)

// Emits the EXACT prefix a Studio chat turn puts in front of the model, so the
// glm-warmup CronJob can replay it byte-for-byte. Skipped unless WARM_OUT is set,
// so it never runs in CI.
//
// This is a TOOL, not an assertion, and it lives in the repo on purpose: what
// gets cached is a token sequence, so a warm-up built from a hand-written copy of
// the prompt drifts silently the first time the real one changes and then warms
// nothing. Generating it from the same functions the handler calls is the only
// version that cannot drift.
//
// Regenerate whenever the system prompt or the tool catalog changes:
//
//	WARM_OUT=/tmp/glm_warm_payload.json go test ./internal/handler/ \
//	  -run TestDumpStudioWarmPayload -v
//	kubectl -n lumid create configmap glm-warmup-payload \
//	  --from-file=payload.json=/tmp/glm_warm_payload.json \
//	  --dry-run=client -o yaml | kubectl apply -f -
//
// SIMPLE=1 emits the Simple-view catalog (the default Studio experience);
// unset emits the full catalog, which is what Advanced sends.
func TestDumpStudioWarmPayload(t *testing.T) {
	out := os.Getenv("WARM_OUT")
	if out == "" {
		t.Skip("set WARM_OUT to emit")
	}
	// ROLE matters as much as SIMPLE. buildSystemPrompt emits a different role
	// block for admin/super_admin, and the cached prefix is a TOKEN SEQUENCE --
	// so a payload built for role=user warms nothing for an admin. That was a
	// real gap: admin@lum.id paid a full cold prefill on every turn while a
	// role=user account was warm, which read as "the model is slow for me".
	role := os.Getenv("ROLE")
	if role == "" {
		role = "user"
	}
	tools := buildToolDefsForRole(role)
	if os.Getenv("SIMPLE") != "" {
		tools = filterSimpleTools(tools)
	}
	payload := map[string]any{
		"model":      "glm-5.3-flash",
		"max_tokens": 8,
		"system":     buildSystemPrompt("warmup-no-such-user", role, ""),
		"tools":      tools,
		"messages":   []map[string]any{{"role": "user", "content": "warmup"}},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: role=%s %d tools, %d bytes (~%d tokens of prefix)", out, role, len(tools), len(b), len(b)/4)
}
