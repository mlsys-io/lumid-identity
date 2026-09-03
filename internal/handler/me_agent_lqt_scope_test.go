package handler

import "strings"
import "testing"

// /xpio/strategies and /xpio/results return scope:"all_tenants" and their rows
// carry no tenant column — `strategies` rows include `payload`, the .lqts source.
// lqt_mailbox_read was open to every role, so any student's chat could read every
// other student's work. Reported 2026-08-31, verified live 2026-09-03.
func TestLqtCrossTenantFeedsAreOperatorOnly(t *testing.T) {
	crossTenant := []string{"strategies", "results"}
	for _, ep := range crossTenant {
		spec, ok := resolveLqtEndpoint(ep)
		if !ok {
			t.Fatalf("endpoint %q vanished from the allowlist", ep)
		}
		if !spec.crossTenant {
			t.Errorf("%q returns every tenant's rows and must be marked crossTenant", ep)
		}
		for _, role := range []string{"", "user", "admin"} {
			res, ok := toolLqtMailboxRead(role, ep, "", 5)
			if ok {
				t.Errorf("role %q must not read the cross-tenant feed %q", role, ep)
			}
			msg, _ := res["error"].(string)
			// The refusal has to point somewhere, or a grounded chat dead-ends.
			if !strings.Contains(msg, "strategy_cycles") {
				t.Errorf("refusal for %q/%q should name the tenant-scoped alternative, got: %s", role, ep, msg)
			}
		}
	}

	// Everything else stays open: venue health is infrastructure telemetry,
	// stats is aggregate counts, and strategy_cycles is tenant-scoped server
	// side — over-blocking these would break legitimate reads silently.
	for _, ep := range []string{"venue_health_nyc", "stats", "signals_venue_mid", "strategy_cycles"} {
		spec, ok := resolveLqtEndpoint(ep)
		if !ok {
			t.Fatalf("endpoint %q vanished from the allowlist", ep)
		}
		if spec.crossTenant {
			t.Errorf("%q should not be operator-gated", ep)
		}
	}
}
