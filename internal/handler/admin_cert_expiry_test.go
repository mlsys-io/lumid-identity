package handler

import "testing"

// The host list is the only parsing in this handler, and it is env-driven so a
// manifest typo lands here rather than in a 500.
func TestCertExpiryHostsParsing(t *testing.T) {
	t.Setenv("CERT_EXPIRY_HOSTS", " lum.id , XP.IO ,lum.id, ")
	got := certExpiryHosts()
	if len(got) != 2 || got[0] != "lum.id" || got[1] != "xp.io" {
		t.Fatalf("expected dedup + lowercase [lum.id xp.io], got %v", got)
	}
}

// An unset/blank var must fall back to the default hosts. Returning none would
// render an EMPTY tile, which is the exact failure this handler was rewritten
// to stop: a blank where a countdown belongs reads as "nothing expiring soon".
func TestCertExpiryHostsFallBackWhenUnset(t *testing.T) {
	t.Setenv("CERT_EXPIRY_HOSTS", "   ")
	if got := certExpiryHosts(); len(got) == 0 {
		t.Fatal("blank env produced no hosts; the tile would render empty")
	}
}
