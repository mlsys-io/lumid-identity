package handler

// Saying "not available here" instead of "nothing here".
//
// A handler that reads a cycle dir or a journal on this pod finds nothing —
// identity mounts exactly one volume, the signing keys — and returned
// {rows: [], total: 0}. That is the same answer it gives for an app that has
// genuinely never run, and the two mean opposite things: one is "wait", the
// other is "waiting will not help". An empty result that actually means OUTAGE
// is the failure this codebase has already paid for twice.
//
// Where the run store can rebuild the answer it does (me_cycle_db_fallback.go).
// What it cannot rebuild — the per-step drill-down, the LLM transcript, the raw
// experiment rows — lives only in the cycle dir, and those handlers say so.
//
// Deliberately an ADDITIVE field on a 200, not an error status: a client that
// ignores it behaves exactly as before, and the surfaces that care can render
// the reason instead of an empty state that reads as "this never ran".

import (
	"os"
	"path/filepath"
)

// runtimeArtifactsReachable reports whether this process can see an app's
// RUNTIME tree (cycles, journal, ledgers) — as opposed to the published bundle,
// which materialiseTenantApp supplies on every pod and which contains none of it.
func runtimeArtifactsReachable(appDir string) bool {
	if appDir == "" {
		return false
	}
	for _, rel := range []string{
		filepath.Join("data", "cycles"),
		filepath.Join("data", "journal.jsonl"),
	} {
		if p, _ := ResolveRuntimeReadPath(appDir, rel); p != "" {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
	}
	return false
}

// unavailableReason returns the sentence to attach to an empty result, or "" if
// the emptiness is genuine (the tree is readable and simply has nothing in it).
//
// `what` names the artifact in the caller's own words, e.g. "this cycle's step
// log" — the message has to say what is missing, not just that something is.
func unavailableReason(appDir, what string) string {
	if runtimeArtifactsReachable(appDir) {
		return "" // readable and empty: the answer is honestly "nothing yet"
	}
	return what + " is not available on this deployment: it lives in the app's " +
		"cycle directory on the scheduler's volume, which this service does not " +
		"mount. Run history and outputs are served from the run store instead; " +
		"per-step detail and transcripts are not."
}
