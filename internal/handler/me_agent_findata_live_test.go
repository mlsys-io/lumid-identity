package handler

import (
	"os"
	"testing"
)

// Live smoke test for the rewritten findata tools. Points FIN_DATA_BASE at the
// public hairpin so it exercises the same /retrieve + /catalog path the chatbox
// uses. Skipped unless FIN_DATA_BASE is set (CI / offline).
func TestDataQueryLive(t *testing.T) {
	if os.Getenv("FIN_DATA_BASE") == "" {
		t.Skip("FIN_DATA_BASE not set; skipping live findata test")
	}
	c, ok := toolDataCatalog("findata", "")
	if !ok {
		t.Fatalf("data_catalog failed: %v", c)
	}
	if _, hasSchemas := c["schemas"]; !hasSchemas {
		t.Fatalf("data_catalog missing schemas: %v", c)
	}
	q, ok := toolDataQuery("SELECT 1 AS ok", "findata", 5)
	if !ok {
		t.Fatalf("data_query failed: %v", q)
	}
	n, _ := q["count"].(int)
	if n != 1 {
		t.Fatalf("expected count 1, got %d (%v)", n, q)
	}
}
