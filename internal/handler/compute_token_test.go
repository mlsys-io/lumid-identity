package handler

import "testing"

// The decision this file guards is "does this app's spec declare a compute
// engine", and it is deliberately pure — no DB, no filesystem. A test that
// needs MySQL is a test that skips in CI, which is how the owner-resolution
// assumption in me_app_cache.go survived a full green suite.

func TestLumilakeEngineIsDetected(t *testing.T) {
	spec := []byte(`
loops:
- name: harvest
  engine: {type: command, module: harvest}
- name: kol_score_fleet
  engine:
    type: lumilake
    workflow: kol_score
    site: home
`)
	if !specDeclaresComputeEngine(spec) {
		t.Fatal("a declared lumilake engine must be detected; without it a chat run " +
			"gets no scoped token and dies on compute.py's shape check")
	}
}

func TestCommandOnlyAppGetsNoToken(t *testing.T) {
	// The overwhelming majority of loops. Minting for these would hand out a
	// live credential to every cycle of every app on the estate.
	spec := []byte(`
loops:
- name: harvest
  engine: {type: command, module: harvest}
- name: analyze
  engine: {type: command, module: analyze}
`)
	if specDeclaresComputeEngine(spec) {
		t.Fatal("a command-only app must not be minted a compute credential")
	}
}

func TestWorkflowsSynonymIsRead(t *testing.T) {
	// `workflows:` is the canonical synonym for `loops:` (W1.1) and the runtime
	// accepts both. Reading only `loops:` would silently deny a credential to an
	// app using the newer spelling — a failure with no error message anywhere,
	// which is the shape this whole cycle kept finding.
	spec := []byte(`
workflows:
- name: score
  engine: {type: lumilake, workflow: w, site: home}
`)
	if !specDeclaresComputeEngine(spec) {
		t.Fatal("`workflows:` is a synonym for `loops:` and must be read too")
	}
}

func TestFlowmeshDoesNotMintACredential(t *testing.T) {
	// Declared-but-unimplemented: LumidOS #102 rejects it at publish and the
	// runtime refuses it at dispatch. A live token for a path that cannot run is
	// a credential handed out for nothing.
	spec := []byte(`
loops:
- name: f
  engine: {type: flowmesh, workflow: w, site: home}
`)
	if specDeclaresComputeEngine(spec) {
		t.Fatal("flowmesh has no runtime path; minting for it grants a token for nothing")
	}
}

func TestGarbageSpecFailsClosed(t *testing.T) {
	// A miss must deny rather than grant. The app then fails at compute.py's own
	// credential check, whose message names the cause.
	for _, spec := range [][]byte{
		[]byte("this is not: [valid: yaml"),
		[]byte(""),
		[]byte("loops: not-a-list"),
		[]byte("name: an-app\nsummary: no loops at all\n"),
	} {
		if specDeclaresComputeEngine(spec) {
			t.Fatalf("must fail CLOSED on unusable spec: %q", string(spec))
		}
	}
}

func TestTheGateIsNotKeyedOnAppName(t *testing.T) {
	// THE REGRESSION THIS FILE EXISTS TO AVOID. lqt_strategy_pat.go gates on a
	// hardcoded slug set; the app was renamed lqt-mailbox -> quant-research, the
	// gate stopped matching, and 83% of live deploy rejections were that one
	// gate missing its app. The same spec must decide the same way under any
	// name, so renaming an app can never silently revoke its credential.
	spec := []byte(`
name: some-brand-new-app-nobody-listed
loops:
- name: score
  engine: {type: lumilake, workflow: w, site: office}
`)
	if !specDeclaresComputeEngine(spec) {
		t.Fatal("the decision must come from the spec, not from a slug allowlist")
	}
}
