// /me/runs/stream — SSE state-transition stream.
//
// The client opens an EventSource (or fetch+ReadableStream) and the
// server pushes one event per state change across all of the caller's
// runs. Light polling under the hood: every 2s we re-walk journal.jsonl
// + n8n executions, diff against the last snapshot, emit one event
// per delta.
//
// Event shape:
//   data: {"type":"started"|"state_changed"|"completed",
//          "run":{...RunRow}}\n\n
//
// Closes cleanly on client disconnect.

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func MeRunsStream(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// SSE headers.
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // nginx: don't buffer SSE
	c.Writer.Flush()

	// Seed snapshot. The first poll establishes baseline; we only emit
	// from the second tick onward (otherwise the client gets a flood
	// on connect, which is the existing /me/runs response shape).
	prev := snapshotRunStates(c, userID)

	// Initial heartbeat so EventSource fires `onopen`.
	fmt.Fprintf(c.Writer, ": connected at %s\n\n", time.Now().UTC().Format(time.RFC3339))
	c.Writer.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-heartbeat.C:
			// Keep proxies happy.
			fmt.Fprintf(c.Writer, ": heartbeat %s\n\n", time.Now().UTC().Format(time.RFC3339))
			c.Writer.Flush()
		case <-ticker.C:
			cur := snapshotRunStates(c, userID)
			emitDeltas(c, prev, cur)
			prev = cur
		}
	}
}

type runSnap struct {
	State string
	Row   RunRow
}

// snapshotRunStates returns a map keyed by RunID → minimal state info.
// We don't keep the full RunRow in prev to bound memory; just enough
// to detect transitions.
func snapshotRunStates(c *gin.Context, userID string) map[string]runSnap {
	now := time.Now().UTC()
	// Look back 1 hour — enough to catch the tail of long-running
	// workflows and any newly-completed cycles since the last tick.
	rows := collectRuns(c, userID, now.Add(-1*time.Hour), now.Add(time.Minute))
	out := make(map[string]runSnap, len(rows))
	for _, r := range rows {
		out[r.RunID] = runSnap{State: r.State, Row: r}
	}
	return out
}

func emitDeltas(c *gin.Context, prev, cur map[string]runSnap) {
	for id, curSnap := range cur {
		prevSnap, existed := prev[id]
		if !existed {
			writeEvent(c, "started", curSnap.Row)
			continue
		}
		if prevSnap.State != curSnap.State {
			eventType := "state_changed"
			if curSnap.State != "running" && prevSnap.State == "running" {
				eventType = "completed"
			}
			writeEvent(c, eventType, curSnap.Row)
		}
	}
}

func writeEvent(c *gin.Context, eventType string, row RunRow) {
	payload := map[string]any{
		"type": eventType,
		"run":  row,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fmt.Fprintf(c.Writer, "data: %s\n\n", b)
	c.Writer.Flush()
}
