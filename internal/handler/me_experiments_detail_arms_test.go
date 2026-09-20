package handler

// The list and the detail of one experiment must agree about its declaration.
//
// `arms` and `dispatch` are DECLARED fields: an arm that has never run exists
// nowhere else. The list row was fixed to carry them — its comment says why,
// "a never-run arm was invisible, and nothing could offer to run it" — and the
// detail payload was not. So the two endpoints answered differently about the
// same object: /me/apps/quant-research/experiments returned kol_alpha with two
// arms and dispatch {loop: kol_strategy}, while
// /me/apps/quant-research/experiments/kol_alpha returned arms: [] and
// dispatch: null. Every dispatch button vanished on the detail route.
//
// This is the shape of bug that survives a passthrough fix applied in one
// place: nothing errors, one caller is right, and which caller you happen to
// use decides whether the feature exists.

import (
	"os"
	"path/filepath"
	"testing"
)

// A bundle whose experiment declares arms and dispatch routing and has NO
// state and NO rows — the case that matters, because a never-run arm is the
// one the declaration is the only source for.
//
// The loaders below are called with an empty userSub/app on purpose:
// readExpStateFor short-circuits before touching the DB in that case, which is
// how the sibling experiments tests stay pure unit tests. Passing a real sub
// segfaults on a nil gorm handle rather than failing an assertion.
func writeArmsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	spec := "experiments:\n" +
		"- id: e1\n" +
		"  metric: {name: real_tape, higher_is_better: true}\n" +
		"  description: two declared arms, neither ever run\n" +
		"  dispatch: {loop: kol_strategy, args: {action: poll}}\n" +
		"  arms:\n" +
		"  - id: current\n" +
		"    description: the passive reference\n" +
		"  - id: musk_v1\n" +
		"    description: self-sufficient\n" +
		"    kol_dataset: musk_tweets_v1\n"
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDetailCarriesDeclaredArms(t *testing.T) {
	dir := writeArmsFixture(t)
	detail, found := loadExperimentDetailFor("", "", dir, "e1")
	if !found {
		t.Fatal("experiment e1 not found in detail")
	}

	arms, _ := detail["arms"].([]map[string]any)
	if len(arms) != 2 {
		t.Fatalf("detail dropped the declared arms: got %#v", detail["arms"])
	}
	ids := []string{}
	for _, a := range arms {
		if s, ok := a["id"].(string); ok {
			ids = append(ids, s)
		}
	}
	if len(ids) != 2 || ids[0] != "current" || ids[1] != "musk_v1" {
		t.Fatalf("arm ids wrong: %v", ids)
	}
	// The arm's own config must survive too — it is what the dispatch sends as
	// the variant, so an arm stripped to {id, description} dispatches a run
	// that measures the wrong thing.
	if arms[1]["kol_dataset"] != "musk_tweets_v1" {
		t.Fatalf("arm config dropped: %#v", arms[1])
	}
}

func TestDetailCarriesDispatchRouting(t *testing.T) {
	dir := writeArmsFixture(t)
	detail, _ := loadExperimentDetailFor("", "", dir, "e1")

	d, _ := detail["dispatch"].(map[string]any)
	if d == nil {
		t.Fatalf("detail dropped dispatch routing: %#v", detail["dispatch"])
	}
	if d["loop"] != "kol_strategy" {
		t.Fatalf("dispatch.loop wrong: %#v", d)
	}
	// dispatch.args is the loop's invocation — the SUBJECT of the run, as
	// opposed to the arm's config. A loop whose metric only lands on a
	// non-default action cannot reach it without this: kol_strategy emits
	// real_tape from `--action poll` and defaults to `generate`, which is why
	// kol_alpha sat at 0 results while its row count climbed.
	args, _ := d["args"].(map[string]any)
	if args == nil || args["action"] != "poll" {
		t.Fatalf("dispatch.args did not survive: %#v", d["args"])
	}
}

// The two endpoints read the same declaration; they must not disagree about
// it. Asserting them against each other rather than against a literal is the
// point — a future field added to one and not the other fails here.
func TestListAndDetailAgreeOnTheDeclaration(t *testing.T) {
	dir := writeArmsFixture(t)
	rows := loadAppExperiments(dir)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row from the list, got %d", len(rows))
	}
	detail, _ := loadExperimentDetailFor("", "", dir, "e1")

	listArms, _ := rows[0]["arms"].([]map[string]any)
	detailArms, _ := detail["arms"].([]map[string]any)
	if len(listArms) != len(detailArms) {
		t.Fatalf("list says %d arms, detail says %d", len(listArms), len(detailArms))
	}

	ld, _ := rows[0]["dispatch"].(map[string]any)
	dd, _ := detail["dispatch"].(map[string]any)
	if (ld == nil) != (dd == nil) {
		t.Fatalf("one endpoint has dispatch and the other does not: list=%#v detail=%#v", ld, dd)
	}
	if ld != nil && ld["loop"] != dd["loop"] {
		t.Fatalf("dispatch.loop disagrees: list=%v detail=%v", ld["loop"], dd["loop"])
	}
}
