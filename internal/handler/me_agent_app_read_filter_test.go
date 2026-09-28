package handler

// app_read must apply the same filters as GET /me/apps/<app>/data, and must
// not hand the model an unbounded result.
//
// Measured 2026-09-28: the chat was told to answer "my backtest results" with
// me://app-data?app=quant-research&tool=runs&loop=backtest. app_read dropped
// every param but app/tool, returned all 2,241 runs of every loop (1.56 MB),
// and deepseek answered that tool result with an empty turn — two chips on
// screen and no answer.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func withFakeRunsTool(t *testing.T, n int) {
	t.Helper()
	readOnlyAppDataTools["zz_fake_runs"] = func(userID, app string) (map[string]any, bool) {
		rows := make([]map[string]any, 0, n)
		for i := 0; i < n; i++ {
			loop := "harvest_outbox"
			if i%3 == 0 {
				loop = "backtest"
			}
			rows = append(rows, map[string]any{"cycle_id": fmt.Sprintf("c%04d", i), "loop": loop})
		}
		return map[string]any{"app": app, "count": n, "runs": rows}, true
	}
	t.Cleanup(func() { delete(readOnlyAppDataTools, "zz_fake_runs") })
}

func readRuns(t *testing.T, src string) map[string]any {
	t.Helper()
	res, err := appReadSource(&gin.Context{}, "sub-1", src)
	if err != nil {
		t.Fatalf("app_read %s: %v", src, err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("app_read %s: result is %T", src, res)
	}
	return m
}

func TestAppReadAppliesTheLoopFilter(t *testing.T) {
	withFakeRunsTool(t, 30)
	m := readRuns(t, "me://app-data?app=quant-research&tool=zz_fake_runs&loop=backtest")
	rows := m["runs"].([]map[string]any)
	if len(rows) != 10 {
		t.Fatalf("loop=backtest kept %d rows, want 10", len(rows))
	}
	for _, r := range rows {
		if r["loop"] != "backtest" {
			t.Fatalf("loop filter let through %v", r)
		}
	}
	if m["count"] != 10 || m["total"] != 30 {
		t.Fatalf("count/total = %v/%v, want 10/30", m["count"], m["total"])
	}
}

func TestAppReadCapsRowsWithoutAnExplicitLimit(t *testing.T) {
	withFakeRunsTool(t, appReadDefaultLimit+50)
	m := readRuns(t, "me://app-data?app=quant-research&tool=zz_fake_runs")
	rows := m["runs"].([]map[string]any)
	if len(rows) != appReadDefaultLimit {
		t.Fatalf("kept %d rows, want the default cap %d", len(rows), appReadDefaultLimit)
	}
	// Newest = tail: the last row must survive the cap.
	if rows[len(rows)-1]["cycle_id"] != fmt.Sprintf("c%04d", appReadDefaultLimit+49) {
		t.Fatalf("cap dropped the newest rows: last=%v", rows[len(rows)-1])
	}
	if m["total"] != appReadDefaultLimit+50 {
		t.Fatalf("total=%v must carry the pre-cap count", m["total"])
	}
	// An explicit limit wins over the default.
	m = readRuns(t, "me://app-data?app=quant-research&tool=zz_fake_runs&limit=5")
	if n := len(m["runs"].([]map[string]any)); n != 5 {
		t.Fatalf("limit=5 kept %d", n)
	}
}

func TestToolResultForModelTruncatesWithAnEnvelope(t *testing.T) {
	small := map[string]any{"ok": true}
	if got := toolResultForModel(small); got != `{"ok":true}` {
		t.Fatalf("small result altered: %s", got)
	}
	big := map[string]any{"blob": strings.Repeat("x", maxToolResultForModel*3)}
	got := toolResultForModel(big)
	if len(got) > maxToolResultForModel+2048 {
		t.Fatalf("truncated payload is %d bytes, cap %d", len(got), maxToolResultForModel)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(got), &env); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if env["truncated"] != true || env["instruction"] == "" {
		t.Fatalf("envelope must say it was truncated and how to narrow: %v", env)
	}
}
