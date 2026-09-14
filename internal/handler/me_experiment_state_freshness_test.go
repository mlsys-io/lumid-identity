package handler

// Which copy of an experiment's state wins.
//
// evaluate() runs on the SCHEDULER's volume and bridges its result here, so the
// DB is the side that MOVES. The old rule returned the on-disk blob whenever it
// carried n_results > 0, which meant a stale materialised copy beat a fresh DB
// row — the wrong way round for the only case that actually occurs. Measured
// 2026-09-09 for a3f48236: judge_panel_parity held 52 rows on the scheduler
// volume against n=17 served here, kol_alpha 12 against 2, both last pushed
// four days earlier, with the panel and the chat quoting the stale figure as
// current.
//
// These exercise the decision directly: the handler needs a live DB, the RULE
// does not.

import (
	"strings"
	"testing"
)

// pickFresher mirrors readExpStateFor's precedence on two already-loaded blobs.
// Kept beside the test so a change to the rule has to change this too.
func pickFresher(disk, db map[string]any) map[string]any {
	if db == nil {
		return disk
	}
	diskWhen, _ := disk["updated_at"].(string)
	dbWhen, _ := db["updated_at"].(string)
	if diskWhen != "" && dbWhen != "" {
		if diskWhen > dbWhen {
			return disk
		}
		return db
	}
	diskN, _ := disk["n_results"].(float64)
	dbN, _ := db["n_results"].(float64)
	if diskN > dbN {
		return disk
	}
	if dbN > 0 || diskN == 0 {
		return db
	}
	return disk
}

func state(n float64, when string) map[string]any {
	s := map[string]any{"n_results": n}
	if when != "" {
		s["updated_at"] = when
	}
	return s
}

func TestFresherStateWins(t *testing.T) {
	cases := []struct {
		name     string
		disk, db map[string]any
		wantN    float64
	}{
		{"the measured incident: stale disk, fresh DB",
			state(17, "2026-09-05T10:00:00Z"), state(52, "2026-09-09T10:00:00Z"), 52},
		{"disk genuinely newer (an operator install running locally)",
			state(80, "2026-09-10T10:00:00Z"), state(52, "2026-09-09T10:00:00Z"), 80},
		{"undated disk, dated DB",
			state(17, ""), state(52, "2026-09-09T10:00:00Z"), 52},
		{"empty disk, real DB",
			state(0, ""), state(52, "2026-09-09T10:00:00Z"), 52},
		{"real disk, empty DB — an app whose bridge never fired",
			state(52, ""), state(0, ""), 52},
		{"no DB row at all",
			state(52, ""), nil, 52},
	}
	for _, c := range cases {
		got, _ := pickFresher(c.disk, c.db)["n_results"].(float64)
		if got != c.wantN {
			t.Errorf("%s: n_results = %v, want %v", c.name, got, c.wantN)
		}
	}
}

// A number with no date is what let a four-day-old figure read as current.
func TestBothPathsCarryAStalenessMarker(t *testing.T) {
	src := loopPatchSrc(t, "me_experiments.go")
	i := strings.Index(src, "func readExpStateFor(")
	block := src[i : i+2000]
	if !strings.Contains(block, `st["state_updated_at"]`) {
		t.Error("the disk path serves no state_updated_at; exactly the installs identity " +
			"CAN read would have no way to say how old their number is")
	}
	if !strings.Contains(src, "func storedExpState") ||
		!strings.Contains(src, `st["state_updated_at"] = row.UpdatedAt`) {
		t.Error("the DB path no longer stamps state_updated_at")
	}
}
