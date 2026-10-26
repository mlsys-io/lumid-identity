package common

import (
	"testing"
	"time"

	"lumid_identity/internal/config"
)

// A blackholed MySQL (no RST, SYNs just vanish) must fail within the 3 s dial timeout, not hang on
// the OS TCP connect timeout — that hang is what lets a backlog pile up during a DB outage.
func TestOpenDBFailsFastOnBlackholedHost(t *testing.T) {
	cfg := &config.Config{}
	cfg.MySQL.Host = "10.255.255.1" // non-routable: connects hang without a dial timeout
	cfg.MySQL.Port = 3306
	cfg.MySQL.User, cfg.MySQL.Password, cfg.MySQL.Database = "u", "p", "d"
	start := time.Now()
	err := OpenDB(cfg)
	took := time.Since(start)
	if err == nil {
		t.Fatal("expected an error against a blackholed host")
	}
	if took > 8*time.Second {
		t.Fatalf("OpenDB took %v; the 3 s dial timeout is not applied", took)
	}
	t.Logf("failed in %v: %v", took.Round(100*time.Millisecond), err)
}
