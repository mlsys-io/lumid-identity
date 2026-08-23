package handler

// casebookCaseDetail is the read behind the Studio case browser. It is the one
// place identity hands case content to an interviewee, so the ground-truth
// guard is the whole point: mbb-consultant's procedure.md calls not reading
// structure_4_ground_truth "the one rule in this file that has no exception".
//
// The guard is INCLUSION-based, and the decisive test is
// TestCasebookCaseDetail_UnknownFieldsAreNotEmitted: a deny-list would leak the
// moment the case schema grows a field, so we assert that an invented field is
// dropped, not merely that today's secret names are absent.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCase(t *testing.T, dir, name string, body map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fullCase() map[string]any {
	return map[string]any{
		"case_id":        "019",
		"version":        "v10",
		"difficulty":     "Hard",
		"industry":       "Optics",
		"topic":          "Profitability",
		"case_type":      "interviewer_driven",
		"source":         map[string]any{"title": "BetaOptics", "year": 2021},
		"opening_prompt": "Our client is BetaOptics…",
		"structure_1_client_basic_context": map[string]any{
			"company": "BetaOptics", "ask": "Why are margins falling?",
		},
		"structure_2_information_upon_request": map[string]any{
			"item_1": map[string]any{"trigger": "asks about costs", "info": "COGS up 12%"},
		},
		"structure_3_case_questions": map[string]any{
			"Q2": map[string]any{
				"type": "qualitative", "question_text": "What are the major expenses?",
				"state_machine": map[string]any{"attempts": 2},
			},
			"Q1": map[string]any{
				"type": "framework", "question_text": "What factors would you consider?",
				"information_to_share_upfront": "Revenue is flat.",
			},
		},
		"structure_4_ground_truth": map[string]any{
			"Q1_ground_truth": map[string]any{
				"total_keypoints": 12, "minimum_expected": 6,
				"pillars": map[string]any{"cost": []string{"COGS", "SG&A"}},
			},
		},
	}
}

func detailOf(t *testing.T, raw map[string]any, id string) (map[string]any, string) {
	t.Helper()
	root := t.TempDir()
	writeCase(t, filepath.Join(root, "data", "seed"), "Case_019_BetaOptics_PK21_v10.json", raw)
	out, ok := casebookCaseDetail(root, id)
	if !ok {
		t.Fatalf("casebookCaseDetail failed: %v", out)
	}
	b, _ := json.Marshal(out)
	return out, string(b)
}

func TestCasebookCaseDetail_NeverLeaksGroundTruth(t *testing.T) {
	_, blob := detailOf(t, fullCase(), "Case_019_BetaOptics_PK21")

	// The answer key, and everything that would reconstruct it.
	for _, secret := range []string{
		"structure_4", "ground_truth", "total_keypoints", "minimum_expected",
		"pillars", "COGS", "SG&A",
	} {
		if strings.Contains(blob, secret) {
			t.Fatalf("ground truth leaked into the analyst view: %q\n%s", secret, blob)
		}
	}

	// structure_2 is the interviewer's release inventory — releasing it up
	// front would hand over facts the candidate is supposed to have to ask for.
	for _, held := range []string{"information_upon_request", "COGS up 12%", "asks about costs"} {
		if strings.Contains(blob, held) {
			t.Fatalf("interviewer-held info leaked: %q", held)
		}
	}

	// Per-question internals the candidate must not see.
	if strings.Contains(blob, "state_machine") {
		t.Fatal("question state_machine leaked")
	}
}

func TestCasebookCaseDetail_UnknownFieldsAreNotEmitted(t *testing.T) {
	raw := fullCase()
	// A field the allow-list has never heard of. A deny-list implementation
	// passes it straight through; the inclusion-based one drops it. This is
	// the test that keeps the guard correct as the case schema evolves.
	raw["structure_5_secret_marking_scheme"] = "answer: 26"
	raw["some_future_answer_key"] = "42"
	_, blob := detailOf(t, raw, "Case_019_BetaOptics_PK21")

	for _, unknown := range []string{"structure_5", "secret_marking_scheme", "answer: 26", "some_future_answer_key", "42"} {
		if strings.Contains(blob, unknown) {
			t.Fatalf("unknown field %q was emitted — the guard is not inclusion-based", unknown)
		}
	}
}

func TestCasebookCaseDetail_ReturnsWhatTheCandidateNeeds(t *testing.T) {
	out, blob := detailOf(t, fullCase(), "Case_019_BetaOptics_PK21")

	for _, want := range []string{"Our client is BetaOptics", "What factors would you consider?", "Revenue is flat.", "BetaOptics"} {
		if !strings.Contains(blob, want) {
			t.Fatalf("expected %q in the analyst view", want)
		}
	}
	qs, _ := out["questions"].([]map[string]any)
	if len(qs) != 2 {
		t.Fatalf("questions = %d, want 2", len(qs))
	}
	// Sorted, so Q1 precedes Q2 — a case is worked in order.
	if qs[0]["q_id"] != "Q1" || qs[1]["q_id"] != "Q2" {
		t.Fatalf("questions out of order: %v, %v", qs[0]["q_id"], qs[1]["q_id"])
	}
}

func TestCasebookCaseDetail_Rejects(t *testing.T) {
	root := t.TempDir()
	writeCase(t, filepath.Join(root, "data", "seed"), "Case_019_BetaOptics_PK21_v10.json", fullCase())

	for _, bad := range []string{"", "../../etc/passwd", "a/b", `a\b`} {
		if _, ok := casebookCaseDetail(root, bad); ok {
			t.Fatalf("accepted bad case id %q", bad)
		}
	}
	if _, ok := casebookCaseDetail(root, "Case_999_Nope"); ok {
		t.Fatal("accepted an id that is not on the roster")
	}
	// The versioned stem must also resolve — the roster and the chat verb
	// disagree on whether _vN is part of the name.
	if _, ok := casebookCaseDetail(root, "Case_019_BetaOptics_PK21_v10"); !ok {
		t.Fatal("versioned stem should resolve to the same case")
	}
}

func TestStripCaseVersion(t *testing.T) {
	cases := map[string]string{
		"Case_019_BetaOptics_PK21_v10": "Case_019_BetaOptics_PK21",
		"Case_001_PremierOil_PK21_v5":  "Case_001_PremierOil_PK21",
		"Case_019_BetaOptics_PK21":     "Case_019_BetaOptics_PK21", // no suffix
		"Case_v_Weird":                 "Case_v_Weird",             // _v not numeric
		"Case_019_v":                   "Case_019_v",               // empty numeric part
	}
	for in, want := range cases {
		if got := stripCaseVersion(in); got != want {
			t.Fatalf("stripCaseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCasebookCaseDetail_StripsAuthoringNotes(t *testing.T) {
	// 6 of the 50 live cases carry a `_note` inside structure_1 — the client
	// brief the CANDIDATE sees. The Python reader has always dropped
	// underscore-prefixed keys (_strip_meta); this Go reader was written later
	// and passed the map through raw, so the note rendered in the Studio case
	// browser as a field called "note" holding CJK instructions to the case
	// author. Caught by looking at a screenshot, not by any assertion.
	raw := fullCase()
	ctx := raw["structure_1_client_basic_context"].(map[string]any)
	ctx["_note"] = "仅含 upfront 信息（casebook 'Prompt' 栏）。严禁混入任何 upon request 内容。"
	ctx["_quality_note"] = "internal QA remark"
	ctx["nested"] = map[string]any{"keep": "yes", "_drop": "no"}

	out, blob := detailOf(t, raw, "Case_019_BetaOptics_PK21")

	for _, meta := range []string{"_note", "_quality_note", "仅含", "internal QA remark", "_drop"} {
		if strings.Contains(blob, meta) {
			t.Fatalf("authoring note %q reached the candidate view", meta)
		}
	}
	cc, _ := out["client_context"].(map[string]any)
	if cc["company"] != "BetaOptics" {
		t.Fatal("stripping removed real content")
	}
	if n, ok := cc["nested"].(map[string]any); !ok || n["keep"] != "yes" {
		t.Fatal("nested real content must survive")
	}
}

func TestStripMetaKeys_MatchesOnThePrefix(t *testing.T) {
	// Match the CONVENTION, not a list of known names — a new `_foo` must be
	// dropped the day it is added, not the day someone spots it on screen.
	in := map[string]any{"a": 1, "_b": 2, "_anything_new": 3}
	got := stripMetaKeys(in)
	if len(got) != 1 || got["a"] != 1 {
		t.Fatalf("stripMetaKeys = %v, want only {a:1}", got)
	}
}
