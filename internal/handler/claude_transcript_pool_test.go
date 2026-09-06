package handler

// pool_id on a transcript is STORED, not derived. The distinction is the whole
// reason the column exists: account -> pool is mutable, so a read-time join
// silently relabels history whenever an operator moves an account.

import (
	"encoding/json"
	"strings"
	"testing"

	"lumid_identity/models"
)

func TestSessionCardCarriesPoolID(t *testing.T) {
	b, err := json.Marshal(sessionCard{ConvKey: "k", Account: "a@x", PoolID: "rsi"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"pool_id":"rsi"`) {
		t.Fatalf("pool_id absent from the session card: %s", b)
	}
}

// Sessions predating the column have no recorded pool. omitempty keeps the key
// off the wire entirely rather than asserting a pool that was never observed —
// an empty string would read as "the default pool" to any consumer applying
// poolIDOrDefault, which is precisely the false history this avoids.
func TestSessionCardOmitsAnUnrecordedPool(t *testing.T) {
	b, _ := json.Marshal(sessionCard{ConvKey: "k", Account: "a@x"})
	if strings.Contains(string(b), "pool_id") {
		t.Fatalf("a session with no recorded pool claimed one: %s", b)
	}
}

// Both rows carry it: the session is last-writer-wins, the turn is per-turn
// truth, because a lease can rotate to another pool's account mid-conversation.
func TestBothSessionAndTurnRecordThePool(t *testing.T) {
	if _, ok := reflectGormTag(models.ClaudeSession{}, "PoolID"); !ok {
		t.Error("ClaudeSession has no PoolID column")
	}
	if _, ok := reflectGormTag(models.ClaudeSessionTurn{}, "PoolID"); !ok {
		t.Error("ClaudeSessionTurn has no PoolID column — per-turn truth is lost when a lease rotates pools")
	}
}
