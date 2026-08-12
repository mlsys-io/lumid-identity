package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The interviewee must see the CLIENT BRIEF and nothing else. Truncating at the
// ground-truth key kept the answer key out but still shipped the interviewer's
// script, every question, and the facts the analyst is supposed to ask for —
// which made the interview non-blind and, live, was echoed into the chat.
func TestCaseContextExposesOnlyTheClientBrief(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	// Shaped like the real dataset file.
	body := `{
	  "case_id": "Case_001_PremierOil_PK21",
	  "industry": "Energy / Oil & Gas",
	  "difficulty": "Easy",
	  "opening_prompt": "Pls be a good interviewee. Q1. What factors... Q4. Calculate savings...",
	  "structure_1_client_basic_context": {"company": "Premier Oil", "situation": "price collapse"},
	  "structure_2_information_upon_request": {"item_1": {"info": "assets only in the North Sea"}},
	  "structure_3_case_questions": {"Q1": {"question_text": "What factors would you consider?"}},
	  "structure_4_ground_truth": {"Q4_ground_truth": {"correct_final_answer": "26000000"}}
	}`
	if err := os.WriteFile(filepath.Join(seed, "Case_001_PremierOil_PK21_v5.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := caseContext(dir, "Case_001_PremierOil_PK21")
	if !ok {
		t.Fatal("expected the case to resolve")
	}
	for _, want := range []string{"Premier Oil", "price collapse", "Energy / Oil & Gas"} {
		if !strings.Contains(got, want) {
			t.Errorf("client brief missing %q", want)
		}
	}
	// Everything the interviewee must NOT see.
	for _, leak := range []string{
		"26000000",               // the answer key
		"ground_truth",           // any trace of it
		"good interviewee",       // the interviewer's script
		"Q4. Calculate",          // later questions revealed up front
		"What factors would you", // structure_3
		"only in the North Sea",  // structure_2: must be ASKED for
	} {
		if strings.Contains(got, leak) {
			t.Errorf("caseContext leaked %q", leak)
		}
	}
}

// A file with no client brief yields nothing rather than a partial dump.
func TestCaseContextRefusesUnknownShape(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	os.MkdirAll(seed, 0o755)
	os.WriteFile(filepath.Join(seed, "Case_X.json"), []byte(`{"notes":"x","structure_4_ground_truth":{"a":1}}`), 0o644)
	if got, ok := caseContext(dir, "Case_X"); ok || got != "" {
		t.Errorf("expected refusal, got ok=%v %q", ok, got)
	}
}
