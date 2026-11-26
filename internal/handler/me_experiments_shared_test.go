package handler

import (
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// A `shared` experiment is measured centrally (operator-scope, e.g. the stock
// backtests). Tenant-run health warnings must not tell every install it is
// broken, and the flag must survive the spec read.
func TestSharedExperimentSkipsTenantRunWarnings(t *testing.T) {
	var d expDecl
	if err := yaml.Unmarshal([]byte("id: kol_alpha\nkind: arms\nshared: true\n"), &d); err != nil || !d.Shared {
		t.Fatalf("shared not parsed: %v %+v", err, d)
	}
	row := gin.H{"id": "kol_alpha", "n_results": 0}
	markZeroReasons(row, "", "", &d, nil, nil)
	if row["shared"] != true {
		t.Fatalf("shared row not marked: %v", row)
	}
	for _, k := range []string{"unfed", "starved", "undispatched"} {
		if _, has := row[k]; has {
			t.Fatalf("tenant-run warning %q on a shared experiment: %v", k, row)
		}
	}

	// Not shared: the unfed marker still fires for a declaration nothing feeds.
	plain := expDecl{ID: "x", Kind: "arms"}
	row2 := gin.H{"id": "x", "n_results": 0}
	markZeroReasons(row2, "", "", &plain, nil, nil)
	if row2["shared"] == true {
		t.Fatalf("a plain experiment was marked shared")
	}
}

func TestSharedStateFallsBackWithoutADatabase(t *testing.T) {
	d := expDecl{ID: "kol_alpha", Shared: true}
	st := map[string]any{"n_results": 3.0}
	if got := sharedExpState(&d, "quant-research", st); got["n_results"] != 3.0 {
		t.Fatalf("tenant state lost when no operator state is readable: %v", got)
	}
}
