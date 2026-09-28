package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func TestCycleIDToRunTsInvertsRunTsToCycleID(t *testing.T) {
	// The detail route is keyed by the cycle id; the store by unix seconds.
	// If these disagree the lookup silently finds nothing and every run shows
	// no children.
	want := time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC).Unix()
	got, ok := cycleIDToRunTs(runTsToCycleID(want))
	if !ok || got != want {
		t.Fatalf("round trip = %d,%v want %d", got, ok, want)
	}
	if got, ok := cycleIDToRunTs("1789390923"); !ok || got != 1789390923 {
		t.Errorf("bare epoch id = %d,%v", got, ok)
	}
	for _, bad := range []string{"", "latest", "12345", "2026-09-14"} {
		if _, ok := cycleIDToRunTs(bad); ok {
			t.Errorf("%q parsed as a run ts", bad)
		}
	}
}

func TestParseComputeJobsShapes(t *testing.T) {
	// No row / no column: an empty LIST, never nil — nil marshals as null and
	// the UI would need a second empty-shape test.
	if got := parseComputeJobs(nil); got == nil || len(got) != 0 {
		t.Errorf("nil column = %#v, want []", got)
	}
	b, _ := json.Marshal(map[string]any{"compute_jobs": parseComputeJobs(nil)})
	if string(b) != `{"compute_jobs":[]}` {
		t.Errorf("empty marshals as %s", b)
	}
	bad := "not json"
	if got := parseComputeJobs(&bad); len(got) != 0 {
		t.Errorf("garbage column = %#v", got)
	}
	raw := `[{"job_id":"req-abcdef12","site":"home","arm":"a1","workers":{"op":"wkr-61"}},` +
		`{"job_id":"req-zzzzzz99","site":""},{"job_id":"","site":"home"}]`
	got := parseComputeJobs(&raw)
	if len(got) != 1 {
		t.Fatalf("got %d jobs, want 1 (half-addresses dropped): %#v", len(got), got)
	}
	if got[0].JobID != "req-abcdef12" || got[0].Site != "home" || got[0].Arm != "a1" ||
		got[0].Workers["op"] != "wkr-61" {
		t.Errorf("job = %#v", got[0])
	}
}

func TestCycleComputeJobsWithoutDBIsEmptyNotNil(t *testing.T) {
	if got := cycleComputeJobs("u", "app", "loop", "20260914T010203Z"); got == nil {
		t.Error("want [] when the store is unreachable")
	}
	if got := cycleComputeJobs("u", "app", "loop", "not-a-ts"); got == nil || len(got) != 0 {
		t.Error("want [] for an unparseable ts")
	}
}

// Against a real store: the owner sees the run's jobs, anyone else sees none.
func TestCycleComputeJobsIsOwnerScoped(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping run-store integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.MeAppRun{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = prev })

	owner := fmt.Sprintf("cj-%d", time.Now().UnixNano()%1_000_000_000)
	runTs := time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC).Unix()
	cj := `[{"job_id":"req-abcdef12","site":"home","arm":"a1"}]`
	row := models.MeAppRun{UserSub: owner, App: "app-cj", Loop: "l", RunTs: runTs, Metrics: "{}", ComputeJobs: &cj}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { db.Where("user_sub = ?", owner).Delete(&models.MeAppRun{}) })

	ts := runTsToCycleID(runTs)
	if got := cycleComputeJobs(owner, "app-cj", "l", ts); len(got) != 1 || got[0].JobID != "req-abcdef12" {
		t.Errorf("owner got %#v", got)
	}
	if got := cycleComputeJobs(owner+"x", "app-cj", "l", ts); len(got) != 0 {
		t.Errorf("another user got %#v — must be owner-scoped", got)
	}
	if got := cycleComputeJobs(owner, "app-cj", "other", ts); len(got) != 0 {
		t.Errorf("another loop got %#v", got)
	}
}
