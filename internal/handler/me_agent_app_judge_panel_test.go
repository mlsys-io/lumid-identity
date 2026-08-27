package handler

// Panel-level judge tests. The unit-level parsing tests live alongside them in
// me_agent_app_judge_test.go; these cover the layer above: which models get
// asked, what happens when one of them cannot answer, and whether this table
// advertises anything the gateway will not serve.
//
// The judge's failure mode is silence, which is why these exist. The scoring
// model was pinned to a constant naming an id lumid-llm had stopped resolving.
// Every scored turn returned "judge returned no parsable score" — for every
// user — and nothing upstream of the model call noticed, because from the app's
// side a 503 and a badly-behaved model are the same event.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSpec(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	// The DOTFILE is canonical — resolve_spec_path prefers it and the publisher
	// always emits it. A reader that takes the legacy mirror sees a stale copy
	// and reports success on it.
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestJudgePanelForReadsAppSpec(t *testing.T) {
	dir := writeSpec(t, `
config:
  judge_panel:
    - deepseek-v4-flash
    - qwen/qwen3.8-27b
  panel_min_agreement: 2
`)
	seats, minAgree := judgePanelFor(dir)
	if len(seats) != 2 || seats[0] != "deepseek-v4-flash" || seats[1] != "qwen/qwen3.8-27b" {
		t.Fatalf("panel not read from spec: %v", seats)
	}
	if minAgree != 2 {
		t.Fatalf("panel_min_agreement = %d, want 2", minAgree)
	}
}

func TestJudgePanelForFallsBackToJudgeModelThenConst(t *testing.T) {
	dir := writeSpec(t, "config:\n  judge_model: deepseek-v4-flash\n")
	if seats, _ := judgePanelFor(dir); len(seats) != 1 || seats[0] != "deepseek-v4-flash" {
		t.Fatalf("judge_model not honoured: %v", seats)
	}
	// An app that declares neither must still score. Falling back to nothing
	// would turn "this app has no opinion" into "this app cannot be used".
	if seats, _ := judgePanelFor(writeSpec(t, "config: {}\n")); len(seats) != 1 || seats[0] != judgeModelID {
		t.Fatalf("no fallback to the const: %v", seats)
	}
	if seats, _ := judgePanelFor(t.TempDir()); len(seats) != 1 || seats[0] != judgeModelID {
		t.Fatalf("missing spec should fall back, got %v", seats)
	}
}

func TestResolveJudgeSeatAcceptsIDAndUpstreamAndRejectsUnknown(t *testing.T) {
	if got := resolveJudgeSeat("deepseek-v4-flash"); got != "deepseek-v4-flash" {
		t.Fatalf("provider id not resolved: %q", got)
	}
	// App authors write model names, not this table's ids.
	if got := resolveJudgeSeat("qwen/qwen3.8-27b"); got == "" {
		t.Fatal("upstream model name did not resolve to a provider id")
	}
	// The important one: an unknown seat must resolve to "" so the caller drops
	// it. Returning any live provider here is how a panel silently collapses
	// into the analyst model marking its own work while still reporting a seat.
	if got := resolveJudgeSeat("qwen3.6-35b-a3b"); got != "" {
		t.Fatalf("bare (unroutable) id resolved to %q — it must be dropped", got)
	}
	if got := resolveJudgeSeat("not-a-model"); got != "" {
		t.Fatalf("unknown seat resolved to %q", got)
	}
}

func TestMedianIntRoundsDownOnDisagreement(t *testing.T) {
	for _, c := range []struct {
		in   []int
		want int
	}{
		{[]int{5}, 5},
		{[]int{4, 6}, 5},
		// Two seats one keypoint apart: claim the smaller number.
		{[]int{4, 5}, 4},
		{[]int{9, 1, 5}, 5},
	} {
		if got := medianInt(c.in); got != c.want {
			t.Fatalf("medianInt(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// A judge with no servable seat must REFUSE, not return a zero. A zero is a
// score, and a wrong score presented with the app's authority is worse than an
// error the caller can see.
func TestJudgeRefusesWhenNoSeatIsServable(t *testing.T) {
	dir := writeSpec(t, "config:\n  judge_panel: [not-a-model]\n")
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"019","structure_1_client_basic_context":{"client":"BetaOptics"},` +
		`"structure_3_case_questions":{"Q1":{"question_text":"why"}},` +
		`"structure_4_ground_truth":{"Q1_ground_truth":{"keypoints":["a","b"]}}}`
	if err := os.WriteFile(filepath.Join(seed, "Case_019_Beta_v1.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, ok := toolAppJudge(context.Background(), "", "user", dir, "Case_019", "why", "an answer", "", "ai")
	if ok {
		t.Fatalf("reported success with no live seat: %v", out)
	}
	if _, isErr := out["error"]; !isErr {
		t.Fatalf("no error reported: %v", out)
	}
	if _, scored := out["score"]; scored {
		t.Fatalf("returned a score with no live seat: %v", out)
	}
}

// The guard that would have caught the outage: every model this table
// advertises must be one lumid-llm will actually serve.
//
// Skips when the gateway is unreachable (offline dev, CI without egress) — a
// connectivity failure is not a provider-table defect and must not read as one.
func TestProviderUpstreamModelsAreRoutable(t *testing.T) {
	base := lumidLLMBase()
	req, err := http.NewRequest("GET", base+"/v1/models", nil)
	if err != nil {
		t.Skipf("cannot build request: %v", err)
	}
	if key, err := kvrunPAT(); err == nil && key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Skipf("lumid-llm unreachable (%v) — not a provider-table failure", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("lumid-llm returned %d listing models", resp.StatusCode)
	}
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil || len(doc.Data) == 0 {
		t.Skip("could not read the model list")
	}
	routable := map[string]bool{}
	for _, m := range doc.Data {
		routable[m.ID] = true
	}
	for _, p := range llmProviders {
		// Only the providers that actually POST to lumid-llm. Anthropic and the
		// subprocess claude-code-* entries answer to a different catalogue.
		if p.endpoint != base+"/v1/messages" {
			continue
		}
		if !routable[p.upstreamModel] {
			t.Errorf("provider %q sends upstreamModel %q, which lumid-llm will not serve — "+
				"every call through it 503s, and nothing above the model call reports why",
				p.id, p.upstreamModel)
		}
	}
}

// A claude-code chip that routes at an in-house model may only name the model
// claude-proxy actually forwards.
//
// claude-sandbox strips the "lumid-llm/" prefix and sends the BARE id to
// claude-proxy (selectBackend), whose denyExternalModelForRole permits exactly
// one non-Anthropic model — the SELF_HOSTED_MODELS entry, deepseek-v4-flash.
// Anything else is refused for EVERY role, deliberately, so that an external
// bill cannot be run up on a model we do not host.
//
// This is not theoretical: claude-code-qwen35 shipped at minRole "user" naming
// qwen3.6-35b-a3b, so it was offered to every ordinary user and refused on every
// call — and the model id had separately gone stale, so it would have 503'd even
// if the policy had allowed it. Two independent failures behind one chip that
// looked fine in the picker.
func TestInHouseCodeChipsNameAServableModel(t *testing.T) {
	const permitted = "deepseek-v4-flash" // mirrors SELF_HOSTED_MODELS in claude-proxy
	for _, p := range llmProviders {
		rest, ok := strings.CutPrefix(p.upstreamModel, "lumid-llm/")
		if !ok {
			continue
		}
		if rest != permitted {
			t.Errorf("provider %q routes in-house at %q, but claude-proxy forwards only %q "+
				"among non-Anthropic models — every call through it is refused for all roles",
				p.id, rest, permitted)
		}
	}
}
