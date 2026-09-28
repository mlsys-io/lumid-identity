package handler

import (
	"encoding/json"
	"fmt"
)

// appReadDefaultLimit caps every row array app_read returns from
// me://app-data when the model passes no `limit`. The newest rows are kept.
const appReadDefaultLimit = 200

// maxToolResultForModel bounds one tool_result handed back to the model.
//
// The browser still gets the full result in the tool_call event (the chip
// renders its item count); only the model's copy is cut. Measured 2026-09-28:
// an unfiltered app_read returned 1.56 MB (~400k tokens), deepseek-v4-flash
// answered it with an empty turn and no error, and the user saw two tool chips
// and no answer. 64 KB is ~16k tokens, well inside every routed model.
const maxToolResultForModel = 64 << 10

// toolResultForModel serialises a tool result for the model, truncating an
// oversized one with an explicit envelope. A truncated JSON prefix alone reads
// as a complete answer, so the envelope says how much was cut and how to ask
// for less.
func toolResultForModel(result map[string]any) string {
	payload, _ := json.Marshal(result)
	if len(payload) <= maxToolResultForModel {
		return string(payload)
	}
	head := string(payload[:maxToolResultForModel])
	env, _ := json.Marshal(map[string]any{
		"truncated":      true,
		"original_bytes": len(payload),
		"shown_bytes":    maxToolResultForModel,
		"instruction": fmt.Sprintf("This result was %d bytes and was CUT to its first %d. "+
			"Do not treat it as complete or count rows from it. Re-call the tool with a "+
			"narrower query (a filter such as loop=/status=, or limit=) and answer from that.",
			len(payload), maxToolResultForModel),
		"partial": head,
	})
	return string(env)
}
