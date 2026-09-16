package handler

// The vision flags drifted off the models they described.
//
// `supportsVision` lived on the CHIP, and the chip outlived the model behind it:
// gemma4 -> qwen3.8-27b -> deepseek-v4-flash, with the flag and its "verified
// via lumid-llm" comment carried along unchanged. autoRouteForTurn routes an
// image turn to the FIRST provider with the flag set, so the product sent every
// image to deepseek-v4-flash, which is text-only.
//
// Measured against the live gateway 2026-09-16:
//
//	deepseek-v4-flash -> 400 "deepseek-v4-flash is not a multimodal model"
//	qwen3.8-27b (chip id lumid-qwen38-27b) -> described the image correctly
//
// and qwen3.8-27b was flagged false. Exactly inverted.
//
// A unit test cannot ask the gateway what a model can do. What it CAN pin is the
// invariant that made the drift matter: if the product accepts images at all,
// somewhere reachable must be able to read one.

import "testing"

// claude-code chips run the sandbox CLI, which DROPS images and says so to the
// user. False is correct and deliberate there — this test must not push anyone
// into "fixing" it.
func isClaudeCode(id string) bool {
	return len(id) >= 12 && id[:12] == "claude-code-"
}

// The invariant. Without it an image turn routes nowhere, or to whichever chip
// happens to be first — which is how this broke.
func TestSomeDirectProviderCanReadAnImage(t *testing.T) {
	var vision []string
	for _, p := range llmProviders {
		if p.supportsVision && !isClaudeCode(p.id) {
			vision = append(vision, p.id)
		}
	}
	if len(vision) == 0 {
		t.Fatal("no direct provider declares supportsVision, so an image turn has " +
			"nowhere to route — the composer accepts images the product cannot read")
	}
	t.Logf("vision-capable direct providers: %v", vision)
}

// Pinned by NAME on purpose. Brittleness is the point: a model id that changes
// should break this and force someone to re-run the one-request gateway check
// documented on the supportsVision field, rather than inherit a stale boolean.
func TestKnownTextOnlyModelsAreNotFlaggedForVision(t *testing.T) {
	// Verified 400 "is not a multimodal model" on 2026-09-16.
	textOnly := map[string]bool{"deepseek-v4-flash": true}
	for _, p := range llmProviders {
		if textOnly[p.id] && p.supportsVision {
			t.Errorf("%s is flagged supportsVision, but the gateway answers "+
				"400 \"is not a multimodal model\" for it. Because autoRouteForTurn "+
				"picks the FIRST vision provider, this one flag captures every image "+
				"in the product.", p.id)
		}
	}
}

// The sandbox branch replaces an image with an explanatory note; claiming vision
// there would route images to a path that silently discards them.
func TestClaudeCodeChipsDoNotClaimVision(t *testing.T) {
	for _, p := range llmProviders {
		if isClaudeCode(p.id) && p.supportsVision {
			t.Errorf("%s claims vision, but the claude-code path drops image blocks "+
				"and substitutes a text note", p.id)
		}
	}
}

// Whichever provider is first with the flag is the one every image reaches, so
// it is worth stating that it is a deliberate choice and not an accident of
// ordering.
func TestTheFirstVisionProviderIsTheOneImagesReach(t *testing.T) {
	for _, p := range llmProviders {
		if !p.supportsVision || isClaudeCode(p.id) {
			continue
		}
		if p.id != "lumid-qwen38-27b" {
			t.Errorf("images now route to %q first. That may be correct — but verify "+
				"it against the gateway before changing this expectation; the previous "+
				"first pick answered 400 to every image for months.", p.id)
		}
		return
	}
}
