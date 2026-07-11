package handler

import "testing"

// TestToolForceIntentPositives — the credentialed-sweep failure phrasings (and
// close variants) MUST classify as control intents so the first model turn is
// sent with tool_choice {"type":"any"} on needsToolHints providers. These are
// exactly the turns where gemma4 answered from memory instead of firing a tool.
func TestToolForceIntentPositives(t *testing.T) {
	positives := []string{
		// sweep's observed misses
		"autoresearch",                // bare-noun query — fired neither list_loops nor loop_status
		"run the momentum loop",       // fired no run tool
		"show my experiments",         // fired list_apps instead of list_experiments
		// one-shot run launches
		"run the morning brief now",
		"execute the case_cycle workflow",
		"launch the crypto-lqa loop",
		"start a cycle for mbb-ai",
		"trigger the loop",
		"stop the workflow",
		// status / listing
		"list my loops",
		"show loops",
		"my loops",
		"list runs for auto-quant",
		"are my loops healthy",
		"loop status",
		"what's the status of my workflows",
		"is the momentum loop running",
		"show my apps",
		"experiments",
		// curated platform imperatives (controlIntentPhrases reuse)
		"install the app auto-quant",
		"publish the app",
		"promote the run",
	}
	for _, c := range positives {
		t.Run(c, func(t *testing.T) {
			if !toolForceIntent(userMsg(c)) {
				t.Errorf("toolForceIntent(%q) = false, want true (control intent must force a tool turn)", c)
			}
		})
	}
}

// TestToolForceIntentNegatives — general questions and non-platform turns must
// NEVER force a tool call: a false positive here degrades ordinary chat (the
// model is denied a prose answer). Precision over recall is the contract.
func TestToolForceIntentNegatives(t *testing.T) {
	negatives := []struct{ name, text string }{
		{"empty", ""},
		{"thanks", "thanks!"},
		{"greeting", "hey, how are you today"},
		{"how-to-question", "how do I run a workflow?"},
		{"what-is-question", "what is an autoresearch loop?"},
		{"explain", "explain the difference between apps and experiments"},
		{"why-question", "why did my loop fail yesterday"},
		{"tell-me-about", "tell me about the loops feature"},
		{"docs", "where are the docs for workflows"},
		{"shell-install", "install numpy please"},
		{"shell-tests", "how do I run the tests?"},
		{"prose-request", "write a poem about infinite loops"},
		{"summarize", "summarize what my apps do"},
		{"no-platform-noun", "start the music"},
		{"verb-only", "just run it faster somehow, whatever works, don't ask"},
		{"long-discussion", "I've been thinking about whether the momentum loop approach even makes sense for crypto markets given the 12h cadence, since by the time a cycle finishes the signal is stale — maybe we should redesign it around event triggers instead"},
	}
	for _, c := range negatives {
		t.Run(c.name, func(t *testing.T) {
			if toolForceIntent(userMsg(c.text)) {
				t.Errorf("toolForceIntent(%q) = true, want false (must not force tools on a general/non-platform turn)", c.text)
			}
		})
	}
}

// TestToolForceIntentScansLastUserMessage — like controlIntent, only the most
// recent user turn counts; stale platform commands earlier in history must not
// keep forcing tools on later conversational turns.
func TestToolForceIntentScansLastUserMessage(t *testing.T) {
	msgs := []chatMessage{
		{Role: "user", Content: "run the momentum loop"}, // earlier — ignored
		{Role: "assistant", Content: "done — run queued"},
		{Role: "user", Content: "thanks, looks great"}, // latest — conversational
	}
	if toolForceIntent(msgs) {
		t.Error("toolForceIntent must scan only the LAST user message")
	}
	msgs2 := []chatMessage{
		{Role: "user", Content: "thanks!"},
		{Role: "assistant", Content: "you're welcome"},
		{Role: "user", Content: "now run the momentum loop"},
	}
	if !toolForceIntent(msgs2) {
		t.Error("toolForceIntent must detect the control intent in the LAST user message")
	}
}

// TestContainsWord pins the whole-word matcher the classifier's precision
// depends on: "run" must not match inside "prune", "app" not inside "apple".
func TestContainsWord(t *testing.T) {
	cases := []struct {
		text, w string
		want    bool
	}{
		{"run the loop", "run", true},
		{"prune the tree", "run", false},
		{"rerun it", "run", false}, // "rerun" is its own verb entry
		{"i like apples", "app", false},
		{"happy to help", "app", false},
		{"open the app now", "app", true},
		{"run mbb-ai's case_cycle", "cycle", true}, // underscore is a boundary: loop/step names split
		{"loop", "loop", true},
		{"loops", "loop", false},
		{"", "loop", false},
	}
	for _, c := range cases {
		if got := containsWord(c.text, c.w); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.text, c.w, got, c.want)
		}
	}
}
