package handler

// Background bash tasks — bash_exec with background=true.
//
// Closes the "no long-running execution" gap vs Claude Code: a build or
// batch job that won't fit the foreground 120s window runs detached
// (up to 30 min), the chat turn returns a task_id immediately, and the
// agent (or the user asking "how's the build?") polls with list_tasks /
// task_output. Running/finished tasks are also surfaced in the system
// prompt via renderTasksBlock so the agent knows about them on the next
// turn without being told.
//
// Execution paths mirror foreground bash_exec:
//   super_admin → in-container shell against /proj, output captured
//                 incrementally into a locked buffer.
//   everyone else → host-side sandbox broker (network-none Docker over
//                 the caller's tenant dir). The broker call is
//                 synchronous, so output lands when the command ends.
//
// State is in-memory only (per container life). Tasks are capped at
// bgMaxPerUser running / bgKeepPerUser retained per user; output is
// capped at bgOutputCap bytes.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	bgMaxTimeoutSec = 1800            // 30 min hard ceiling
	bgDefaultSec    = 600             // default when caller passes a foreground-ish timeout
	bgMaxPerUser    = 2               // concurrently running background tasks per user
	bgKeepPerUser   = 10              // finished tasks retained per user
	bgOutputCap     = 1 * 1024 * 1024 // 1 MB captured output per task
	bgReturnCap     = 100 * 1024      // max bytes returned by task_output
)

type bgTask struct {
	ID         string
	Command    string
	Status     string // running | done | error | timeout
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time

	mu  sync.Mutex
	out []byte
}

// Write implements io.Writer so the in-container path can stream
// stdout/stderr into the task as the command runs.
func (t *bgTask) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.out) < bgOutputCap {
		room := bgOutputCap - len(t.out)
		if len(p) > room {
			t.out = append(t.out, p[:room]...)
		} else {
			t.out = append(t.out, p...)
		}
	}
	return len(p), nil
}

func (t *bgTask) appendOutput(s string) { _, _ = t.Write([]byte(s)) }

func (t *bgTask) snapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	row := map[string]any{
		"task_id":    t.ID,
		"command":    t.Command,
		"status":     t.Status,
		"started_at": t.StartedAt.UTC().Format(time.RFC3339),
		"bytes":      len(t.out),
	}
	if !t.FinishedAt.IsZero() {
		row["finished_at"] = t.FinishedAt.UTC().Format(time.RFC3339)
		row["exit_code"] = t.ExitCode
	}
	return row
}

type userTasks struct {
	mu    sync.Mutex
	tasks map[string]*bgTask
	order []string // creation order, for pruning + stable listing
}

var bgTaskStore sync.Map // userID → *userTasks

func tasksFor(userID string) *userTasks {
	actual, _ := bgTaskStore.LoadOrStore(userID, &userTasks{tasks: map[string]*bgTask{}})
	return actual.(*userTasks)
}

// startBackgroundBash validates and launches a detached bash task,
// returning {task_id, status:"running"} immediately. The approval gate
// (or an "always allow" grant) has already fired by the time we're
// called — same as foreground bash_exec.
func startBackgroundBash(userID, role, command string, timeoutSec int) (map[string]any, bool) {
	for _, phrase := range bashBlockedPhrases {
		if strings.Contains(command, phrase) {
			return map[string]any{"error": "command blocked by safety policy"}, false
		}
	}
	if !checkExecRateLimit(userID) {
		return map[string]any{"error": "execution rate limit: max 6 per minute"}, false
	}
	if timeoutSec <= 0 || timeoutSec > bgMaxTimeoutSec {
		timeoutSec = bgDefaultSec
	} else if timeoutSec <= 120 {
		// Caller passed a foreground-scale timeout to a background job —
		// give it the background default instead of killing a build at 30s.
		timeoutSec = bgDefaultSec
	}

	ut := tasksFor(userID)
	ut.mu.Lock()
	running := 0
	for _, t := range ut.tasks {
		t.mu.Lock()
		if t.Status == "running" {
			running++
		}
		t.mu.Unlock()
	}
	if running >= bgMaxPerUser {
		ut.mu.Unlock()
		return map[string]any{"error": fmt.Sprintf("max %d background tasks already running — wait or check list_tasks", bgMaxPerUser)}, false
	}
	task := &bgTask{
		ID:        "task-" + uuid.New().String()[:8],
		Command:   command,
		Status:    "running",
		StartedAt: time.Now(),
	}
	ut.tasks[task.ID] = task
	ut.order = append(ut.order, task.ID)
	// Prune oldest FINISHED tasks beyond the retention cap.
	if len(ut.order) > bgKeepPerUser {
		kept := ut.order[:0]
		excess := len(ut.order) - bgKeepPerUser
		for _, id := range ut.order {
			t := ut.tasks[id]
			t.mu.Lock()
			finished := t.Status != "running"
			t.mu.Unlock()
			if excess > 0 && finished {
				delete(ut.tasks, id)
				excess--
				continue
			}
			kept = append(kept, id)
		}
		ut.order = kept
	}
	ut.mu.Unlock()

	go runBackgroundBash(task, userID, role, timeoutSec)

	return map[string]any{
		"task_id": task.ID,
		"status":  "running",
		"note":    fmt.Sprintf("running detached (up to %ds) — check with task_output('%s')", timeoutSec, task.ID),
	}, true
}

func runBackgroundBash(task *bgTask, userID, role string, timeoutSec int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	finish := func(status string, exitCode int) {
		task.mu.Lock()
		task.Status = status
		task.ExitCode = exitCode
		task.FinishedAt = time.Now()
		task.mu.Unlock()
	}

	if role != "super_admin" {
		// Sandbox broker — synchronous; output arrives at completion.
		result, ok := bashViaSandboxBroker(ctx, userID, task.Command, timeoutSec)
		if out, _ := result["output"].(string); out != "" {
			task.appendOutput(out)
		}
		if e, _ := result["error"].(string); e != "" {
			task.appendOutput("\n[error] " + e)
		}
		ec := -1
		if v, okEC := result["exit_code"].(float64); okEC {
			ec = int(v)
		}
		if to, _ := result["timed_out"].(bool); to || ctx.Err() == context.DeadlineExceeded {
			finish("timeout", ec)
			return
		}
		if ok {
			finish("done", ec)
		} else {
			finish("error", ec)
		}
		return
	}

	// super_admin: in-container shell against the codebase tree, output
	// streamed incrementally into the task buffer.
	shell := "bash"
	if _, err := exec.LookPath("bash"); err != nil {
		shell = "sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-c", task.Command)
	cmd.Dir = writeRoot(userID, role)
	cmd.Stdout = task
	cmd.Stderr = task

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		task.appendOutput("\n[killed: timed out]")
		finish("timeout", -1)
		return
	}
	if err != nil {
		ec := -1
		if ee, ok := err.(*exec.ExitError); ok {
			ec = ee.ExitCode()
		} else {
			task.appendOutput("\n[error] " + err.Error())
		}
		finish("error", ec)
		return
	}
	finish("done", 0)
}

// toolListTasks — list_tasks tool.
func toolListTasks(userID string) map[string]any {
	ut := tasksFor(userID)
	ut.mu.Lock()
	defer ut.mu.Unlock()
	rows := make([]map[string]any, 0, len(ut.order))
	for _, id := range ut.order {
		if t, ok := ut.tasks[id]; ok {
			rows = append(rows, t.snapshot())
		}
	}
	return map[string]any{"tasks": rows, "count": len(rows)}
}

// toolTaskOutput — task_output tool. Returns up to the last bgReturnCap
// bytes of captured output plus status.
func toolTaskOutput(userID, taskID string) (map[string]any, bool) {
	if taskID == "" {
		return map[string]any{"error": "task_id required"}, false
	}
	ut := tasksFor(userID)
	ut.mu.Lock()
	task, ok := ut.tasks[taskID]
	ut.mu.Unlock()
	if !ok {
		return map[string]any{"error": "unknown task: " + taskID}, false
	}
	task.mu.Lock()
	out := task.out
	truncated := false
	if len(out) > bgReturnCap {
		out = out[len(out)-bgReturnCap:]
		truncated = true
	}
	res := map[string]any{
		"task_id":   task.ID,
		"status":    task.Status,
		"output":    string(out),
		"truncated": truncated,
	}
	if !task.FinishedAt.IsZero() {
		res["exit_code"] = task.ExitCode
	} else if len(out) == 0 {
		res["note"] = "still running — sandboxed tasks deliver output on completion"
	}
	task.mu.Unlock()
	return res, true
}

// renderTasksBlock — appended to the system prompt so the agent knows
// about in-flight/finished background work on the next turn. Empty
// string when the user has no tasks.
func renderTasksBlock(userID string) string {
	v, ok := bgTaskStore.Load(userID)
	if !ok {
		return ""
	}
	ut := v.(*userTasks)
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if len(ut.order) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n\n## Background tasks\n")
	for _, id := range ut.order {
		t, ok := ut.tasks[id]
		if !ok {
			continue
		}
		t.mu.Lock()
		cmd := t.Command
		if len(cmd) > 80 {
			cmd = cmd[:80] + "…"
		}
		sb.WriteString(fmt.Sprintf("- %s [%s] `%s`\n", t.ID, t.Status, cmd))
		t.mu.Unlock()
	}
	sb.WriteString("Use task_output(task_id) to read results.")
	return sb.String()
}
