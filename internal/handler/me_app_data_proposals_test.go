package handler

// The proposals app-data tool, on the two things a surface actually depends on.
//
// A surface table renders TOP-LEVEL keys, and filterAppData matches top-level
// keys only and fails CLOSED on a field no row has — so a row whose fields are
// nested renders as a permanently empty table under a heading claiming
// otherwise. That has happened here before (lqt-mailbox's "Backtests for this
// strategy" matched nothing for every strategy because the id it filtered on
// was buried in metrics.command_engine). So: assert the flat shape survives,
// and assert the nested detail is dropped rather than reaching a table cell as
// [object Object].
//
// The slate fixture is the real output shape of quant-research's
// propose_experiments verb, not an invented one.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const proposalSlate = `{
  "ok": true, "mode": "annotate", "app": "quant-research", "ts": 1789788021,
  "n": 2, "will_collect": 1, "will_be_invisible": 1,
  "proposals": [
    {"id": "kol_lean_conviction", "seat": "advocate", "kind": "arms",
     "metric_name": "real_tape", "hypothesis": "Conviction scaling moves the rate.",
     "verdict": "will_collect", "verdict_reason": "Nothing found.",
     "arms": [{"id": "musk_v1"}, {"id": "conviction_scaled"}],
     "findings": []},
    {"id": "pnl_parity_check", "seat": "archivist", "kind": "arms",
     "metric_name": "realized_pnl_rate", "hypothesis": "PnL is at parity.",
     "verdict": "will_be_invisible",
     "verdict_reason": "metric.name='realized_pnl_rate' is not emitted by backtest.",
     "arms": [{"id": "current"}],
     "findings": [{"code": "metric_not_emitted", "severity": "block", "detail": "..."}]}
  ]
}`

// stageSlate writes a slate into an app dir laid out the way resolveAppDir
// finds it, and returns the dir.
func stageSlate(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	pd := filepath.Join(dir, ".lumid", "proposals")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pd, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

// readSlate mirrors what the tool does once resolveAppDir has produced a dir,
// so the shape contract is testable without standing up a tenant tree.
func readSlate(t *testing.T, dir string) []map[string]any {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, ".lumid", "proposals"))
	if err != nil {
		return nil
	}
	newest := ""
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" && e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".lumid", "proposals", newest))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var slate struct {
		Proposals []map[string]any `json:"proposals"`
	}
	if err := json.Unmarshal(raw, &slate); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := make([]map[string]any, 0, len(slate.Proposals))
	for _, p := range slate.Proposals {
		row := map[string]any{}
		for k, v := range p {
			if k == "findings" || k == "arms" {
				continue
			}
			row[k] = v
		}
		out = append(out, row)
	}
	return out
}

func TestProposalRowsAreFlatEnoughForASurfaceTable(t *testing.T) {
	rows := readSlate(t, stageSlate(t, "1789788021.json", proposalSlate))
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	// Every column ui/proposals.md declares must exist on every row, or the
	// table filters to nothing and the page reads as "no candidates".
	for _, col := range []string{"verdict", "seat", "id", "metric_name", "hypothesis", "verdict_reason"} {
		for i, r := range rows {
			if v, ok := r[col]; !ok || v == "" {
				t.Errorf("row %d missing surface column %q", i, col)
			}
		}
	}
}

func TestNestedDetailIsDroppedFromRows(t *testing.T) {
	for _, r := range readSlate(t, stageSlate(t, "1789788021.json", proposalSlate)) {
		for _, k := range []string{"findings", "arms"} {
			if _, present := r[k]; present {
				t.Errorf("%q reached a table row; it renders as [object Object]", k)
			}
		}
	}
	// The blocking reason must survive as prose, since dropping `findings` is
	// only acceptable because verdict_reason carries the same information.
	rows := readSlate(t, stageSlate(t, "1789788021.json", proposalSlate))
	if rows[1]["verdict_reason"] == "" {
		t.Error("a blocked proposal lost its reason along with its findings")
	}
}

func TestNewestSlateWins(t *testing.T) {
	dir := stageSlate(t, "1000000000.json", proposalSlate)
	newer := `{"proposals":[{"id":"newer","seat":"advocate","verdict":"will_collect",
	  "metric_name":"real_tape","hypothesis":"h","verdict_reason":"r"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".lumid", "proposals", "2000000000.json"),
		[]byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := readSlate(t, dir)
	if len(rows) != 1 || rows[0]["id"] != "newer" {
		t.Fatalf("newest slate should win, got %v", rows)
	}
}

func TestNoSlateIsEmptyNotAnError(t *testing.T) {
	// An app that has never proposed anything must render its empty state,
	// not an error — the surface runs unattended on page load.
	if rows := readSlate(t, t.TempDir()); len(rows) != 0 {
		t.Fatalf("want no rows, got %d", len(rows))
	}
}

func TestProposalsIsRegisteredAndArgumentFree(t *testing.T) {
	fn, ok := readOnlyAppDataTools["proposals"]
	if !ok {
		t.Fatal("proposals is not in the surface allowlist, so ui/proposals.md gets a 400")
	}
	// The allowlist's contract is "no argument but the app". A missing app
	// must fail closed rather than reading something else.
	if _, okRes := fn("nobody", ""); okRes {
		t.Error("an empty app name must not resolve")
	}
}
