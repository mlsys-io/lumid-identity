package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanChatTitleStripsModelFormattingHabits(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Rotating the LB cert", "Rotating the LB cert"},
		{`"Rotating the LB cert"`, "Rotating the LB cert"},
		{"Title: Rotating the LB cert", "Rotating the LB cert"},
		{"Rotating the LB cert.", "Rotating the LB cert"},
		{"“Rotating the LB cert”", "Rotating the LB cert"},
		{"  Rotating   the LB   cert \n\nHope that helps!", "Rotating the LB cert"},
		{"\n\nRotating the LB cert", "Rotating the LB cert"},
		{"Kubernetes 部署问题。", "Kubernetes 部署问题"},
		// The escape hatch the prompt asks for, and the empty case.
		{"none", ""},
		{"None", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := cleanChatTitle(c.in); got != c.want {
			t.Errorf("cleanChatTitle(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanChatTitleCapsLength(t *testing.T) {
	got := cleanChatTitle(strings.Repeat("ü", 200))
	if n := len([]rune(got)); n != chatTitleSummaryMaxLen+1 { // +1 for the ellipsis
		t.Fatalf("len = %d runes, want %d", n, chatTitleSummaryMaxLen+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected an ellipsis suffix, got %q", got)
	}
}

// A lone user message must NOT trigger generation: inferTitle already covers
// it, and calling a model to restate one message is pure waste.
func TestChatTitleExcerptNeedsBothSides(t *testing.T) {
	if _, ok := chatTitleExcerpt([]map[string]any{
		{"role": "user", "content": "hi"},
	}); ok {
		t.Error("excerpt built from a user message with no reply")
	}
	if _, ok := chatTitleExcerpt([]map[string]any{
		{"role": "assistant", "content": "hi"},
	}); ok {
		t.Error("excerpt built from an assistant message with no question")
	}
	if _, ok := chatTitleExcerpt(nil); ok {
		t.Error("excerpt built from an empty transcript")
	}
}

func TestChatTitleExcerptUsesFirstExchangeAndBlockContent(t *testing.T) {
	got, ok := chatTitleExcerpt([]map[string]any{
		{"role": "user", "content": "how do I rotate the LB cert"},
		{"role": "assistant", "content": []any{
			map[string]any{"type": "thinking", "thinking": "SHOULD NOT APPEAR"},
			map[string]any{"type": "tool_use", "name": "bash", "input": map[string]any{}},
			map[string]any{"type": "text", "text": "Run the acme.sh reconcile job."},
		}},
		{"role": "user", "content": "LATER MESSAGE"},
	})
	if !ok {
		t.Fatal("expected an excerpt")
	}
	for _, bad := range []string{"SHOULD NOT APPEAR", "LATER MESSAGE"} {
		if strings.Contains(got, bad) {
			t.Errorf("excerpt leaked %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "rotate the LB cert") || !strings.Contains(got, "acme.sh reconcile") {
		t.Errorf("excerpt missing the first exchange:\n%s", got)
	}
}

// The whole point of the title_summary flag: a later save must not revert a
// generated title to the truncated first message.
func TestSetChatTitleIsWriteOnceAndPreservesTranscript(t *testing.T) {
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())

	userID := "user-1"
	cdir := chatsDir(userID)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := "chat-0123456789abcdef"
	orig := chatRecord{
		ID:    id,
		Title: "how do I rotate the LB cert and then...",
		Messages: []map[string]any{
			{"role": "user", "content": "how do I rotate the LB cert"},
			{"role": "assistant", "content": "Run the reconcile job."},
		},
	}
	b, _ := json.Marshal(orig)
	if err := os.WriteFile(filepath.Join(cdir, id+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := setChatTitle(userID, id, "Rotating the LB cert"); err != nil {
		t.Fatalf("setChatTitle: %v", err)
	}
	read := func() chatRecord {
		raw, err := os.ReadFile(chatPath(userID, id))
		if err != nil {
			t.Fatal(err)
		}
		var r chatRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := read()
	if got.Title != "Rotating the LB cert" {
		t.Errorf("title = %q", got.Title)
	}
	if !got.TitleSummary {
		t.Error("title_summary not set")
	}
	if len(got.Messages) != 2 {
		t.Errorf("transcript clobbered: %d messages", len(got.Messages))
	}

	// Second pass must yield to the existing summary rather than overwrite it.
	if err := setChatTitle(userID, id, "A DIFFERENT TITLE"); err != nil {
		t.Fatalf("second setChatTitle: %v", err)
	}
	if got := read(); got.Title != "Rotating the LB cert" {
		t.Errorf("summary overwritten: %q", got.Title)
	}
}

func TestMaybeSummarizeChatTitleRespectsKillSwitch(t *testing.T) {
	t.Setenv("LUMID_CHAT_TITLE_SUMMARY", "0")
	if chatTitleSummaryEnabled() {
		t.Fatal("kill switch not honoured")
	}
	// Must return without spawning work (no LLM configured in the test env).
	maybeSummarizeChatTitle("user-1", "chat-0123456789abcdef", []map[string]any{
		{"role": "user", "content": "q"},
		{"role": "assistant", "content": "a"},
	})
}
