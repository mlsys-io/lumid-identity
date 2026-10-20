package handler

// Cold sweep integration tests (need MySQL):
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run ColdSweep

import (
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func setupColdSweepDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping cold sweep integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.ClaudeSessionTurn{}, &models.ClaudeSession{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	orig := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = orig })
	return db
}

// seedSweepSession records a session last active at lastTs with n blobbed
// turns, and puts their blobs in the hot fake.
func seedSweepSession(t *testing.T, db *gorm.DB, hot *fakeS3, conv string, lastTs time.Time, n int) {
	t.Helper()
	if err := db.Create(&models.ClaudeSession{ConvKey: conv, UserSub: "sweep-test", FirstTs: lastTs, LastTs: lastTs, TurnCount: n}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	for i := 0; i < n; i++ {
		bk := conv + "/" + string(rune('0'+i))
		if err := db.Create(&models.ClaudeSessionTurn{ConvKey: conv, TurnIndex: i, Ts: lastTs, BlobKey: bk}).Error; err != nil {
			t.Fatalf("seed turn: %v", err)
		}
		putTurn(hot, "hot", bk)
	}
	t.Cleanup(func() {
		db.Unscoped().Where("conv_key = ?", conv).Delete(&models.ClaudeSessionTurn{})
		db.Unscoped().Where("conv_key = ?", conv).Delete(&models.ClaudeSession{})
	})
}

func countPrefix(f *fakeS3, prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// An idle session moves whole: every blob lands in cold, verified, and its hot
// keys are gone; a recent session is untouched; a second run is a clean no-op.
func TestColdSweepMovesIdleSessionsOnly(t *testing.T) {
	db := setupColdSweepDB(t)
	hotF, hot := newFakeS3(t)
	coldF, cold := newFakeS3(t)
	withStores(t, hot, cold)
	seedSweepSession(t, db, hotF, "sweepold000000000000000000000001", time.Now().Add(-40*24*time.Hour), 2)
	seedSweepSession(t, db, hotF, "sweepnew000000000000000000000001", time.Now().Add(-2*24*time.Hour), 1)

	st, err := SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour, Workers: 2})
	if err != nil {
		t.Fatalf("sweep: %v (%+v)", err, st)
	}
	if st.Moved != 1 || st.Objects != 6 {
		t.Fatalf("stats = %+v, want 1 session / 6 objects moved", st)
	}
	if n := countPrefix(hotF, "/hot/claude-sessions/sweepold"); n != 0 {
		t.Fatalf("%d hot objects left for the idle session", n)
	}
	if n := countPrefix(coldF, "/cold/claude-sessions/sweepold"); n != 6 {
		t.Fatalf("cold has %d objects for the idle session, want 6", n)
	}
	if n := countPrefix(hotF, "/hot/claude-sessions/sweepnew"); n != 3 {
		t.Fatalf("recent session lost hot objects: %d left, want 3", n)
	}
	if _, _, resp := getTurnBlobs("sweepold000000000000000000000001/1"); string(resp) != `"response.gz"` {
		t.Fatalf("moved turn does not read back: %q", resp)
	}

	// A clean run stamps cold_at, so the next run does not revisit the session.
	st, err = SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour, Workers: 2})
	if err != nil || st.Sessions != 0 {
		t.Fatalf("re-run = %+v, %v; want the swept session skipped", st, err)
	}

	// Without the marker (e.g. moved by hand), a re-run finds it already cold
	// via hot 404 + cold HEAD and stamps it.
	db.Model(&models.ClaudeSession{}).Where("conv_key = ?", "sweepold000000000000000000000001").Update("cold_at", nil)
	st, err = SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour, Workers: 2})
	if err != nil || st.AlreadyCold != 1 || st.Moved != 0 {
		t.Fatalf("unmarked re-run = %+v, %v; want one already-cold session and no error", st, err)
	}

	// A session that resumed after its move (last_ts > cold_at) is swept again.
	db.Model(&models.ClaudeSession{}).Where("conv_key = ?", "sweepold000000000000000000000001").
		Update("cold_at", time.Now().Add(-50*24*time.Hour))
	st, err = SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour, Workers: 2})
	if err != nil || st.Sessions != 1 {
		t.Fatalf("resumed re-run = %+v, %v; want the session revisited", st, err)
	}
}

// A copy that does not read back identically must leave the session entirely
// in the hot store and fail the run.
func TestColdSweepKeepsHotWhenVerifyFails(t *testing.T) {
	db := setupColdSweepDB(t)
	hotF, hot := newFakeS3(t)
	coldF, cold := newFakeS3(t)
	coldF.corrupt = true
	withStores(t, hot, cold)
	seedSweepSession(t, db, hotF, "sweepbad000000000000000000000001", time.Now().Add(-40*24*time.Hour), 2)

	st, err := SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour, Workers: 1})
	if err == nil || st.Failed != 1 {
		t.Fatalf("sweep = %+v, %v; want one failed session and an error", st, err)
	}
	if n := countPrefix(hotF, "/hot/claude-sessions/sweepbad"); n != 6 {
		t.Fatalf("hot objects deleted despite failed verify: %d left, want 6", n)
	}
}

func TestColdSweepRefusesWithoutColdTierOrBelowFloor(t *testing.T) {
	_, hot := newFakeS3(t)
	withStores(t, hot, nil)
	if _, err := SweepColdSessions(ColdSweepOptions{ColdAfter: 30 * 24 * time.Hour}); err == nil {
		t.Fatal("sweep ran without a cold tier")
	}
	_, cold := newFakeS3(t)
	withStores(t, hot, cold)
	if _, err := SweepColdSessions(ColdSweepOptions{ColdAfter: 24 * time.Hour}); err == nil {
		t.Fatal("sweep accepted a cold-after below the 7-day floor")
	}
}
