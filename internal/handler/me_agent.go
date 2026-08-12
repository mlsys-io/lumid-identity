package handler

// /api/v1/me/agent/* — conversational shell. The "natural interaction"
// layer that replaces button-and-form crutches in the 5-tab dashboard.
//
// POST /api/v1/me/agent/chat
//   Body: {"messages": [{"role":"user","content":"..."}, ...]}
//   Returns: {"reply": "...", "tool_calls": [...], "usage": {...}}
//
// The user talks; the agent calls /me/* tools on their behalf. Same
// backend write surface that a hypothetical UI button would hit, just
// reached via natural-language intent instead of a click.
//
// Architecture:
//   1. We forward to Anthropic Messages API (api.anthropic.com/v1/messages)
//      with a system prompt + tools[] definitions + the user's
//      conversation history.
//   2. If Claude returns a tool_use block, we execute the tool locally
//      against the calling user's tenant root + the existing /me/*
//      handler logic, append the tool_result to the conversation, and
//      call Claude again. Loop until Claude returns a plain text block.
//   3. We track total tokens used + write to a usage_events row for
//      the per-user budget cap (P4 follow-up).
//
// Server-funded: every user's chat uses the operator's Anthropic key
// (ANTHROPIC_API_KEY env, or read from /home/webmaster/.api_keys/anthropic
// as a fallback). Per-user daily token budget enforcement lands as a
// follow-up — for now, every chat just hits the operator's account.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	anthropicEndpoint     = "https://api.anthropic.com/v1/messages"
	anthropicVersion      = "2023-06-01"
	anthropicModel        = "claude-haiku-4-5-20251001"
	maxToolLoopIterations = 50    // Claude Code parity — long refactors routinely need dozens of steps
	maxTokensPerTurn      = 16384 // default per-turn output cap; providers may override via maxOutputTokens
)

// ── Tool approval registry ──────────────────────────────────────────────────
// Before dispatching destructive tools, we pause and wait for the user to
// approve or deny via POST /api/v1/me/agent/chat/tool-approve.

var (
	toolApprovals    sync.Map                 // approval_id → chan bool
	sandboxSemaphore = make(chan struct{}, 6) // global cap: 6 concurrent bash sandboxes
	userSandboxMu    sync.Map                 // userID → chan struct{} (per-user cap: 1)
	userExecRateMu   sync.Mutex
	userExecCounts   = map[string][]int64{} // userID → slice of Unix timestamps (last 60s)
)

// destructiveTools is the set of tool names that require user approval before
// execution. Includes both built-in mutating tools and LumidOS ops that push
// or run live state.
var destructiveTools = map[string]bool{
	"bash_exec":   true,
	"write_file":  true,
	"edit_file":   true,
	"multi_edit":  true,
	"app_push":    true,
	"app_install": true,
	// Phase 4 (app -> agent) canonical names. The old app_* names stay above
	// as aliases so in-flight clients/prompts keep working; both route to the
	// same LumidOS bridge handler (see agentToolAlias + dispatchTool).
	"agent_push":    true,
	"agent_install": true,
	// NOTE: running an ALREADY-INSTALLED workflow (run_loop / app_run /
	// agent_run / run_loop_now) is intentionally NOT gated. It is the core,
	// non-destructive action of the assistant — firing a one-shot cycle of a
	// loop the user already installed. Gating it forced an approval round-trip
	// that the tool-using model never completed, so "run X" never ran. Genuine
	// mutations (push/install/delete/billing/submit_workflow/live-trade) stay
	// gated below.
	"submit_workflow": true,
	"xp_ingest":       true,
	// C3 observability/action tools that mutate state.
	"review_action":  true,
	"app_config_set": true,
	// Generic app-ops mutations (operate any app from chat). Reads
	// (app_read/app_actions/show_app_surface/app_ui_get) are NOT gated.
	"app_action": true,
	"qa_call":    true,
	// App-surface authoring + run lifecycle (close the UI-only gaps). Writes
	// land only in the caller's OWN tenant install / advisory run markers.
	"app_ui_set":      true,
	"app_ui_generate": true,
	"run_promote":     true,
	"run_discard":     true,
	// Prompt editor writes (own tenant app only) + branch-with-intention.
	// Reads (app_prompt_list/app_prompt_get/search_run_log) are NOT gated.
	"app_prompt_set":   true,
	"app_prompt_reset": true,
	"branch_run":       true,
	// Admin control-plane writes (admin_users / admin_clusters reads are NOT gated).
	"admin_set_user_role":      true,
	"admin_set_user_status":    true,
	"admin_grant_access":       true,
	"admin_set_worker_pricing": true,
	// Account self-service writes (account_list_pat is NOT gated).
	"account_revoke_pat":  true,
	"account_set_profile": true,
	"delete_loop":         true,
	// Operator control-plane: remediation mutates live stack state (super_admin
	// only). operator_healthcheck is read-only and intentionally NOT gated.
	"operator_remediate": true,
}

// lumidosToolNames is the set of tool names dispatched to the LumidOS schedule
// server bridge (POST /api/v1/tools/invoke at LUMIDOS_URL).
var lumidosToolNames = map[string]bool{
	// Apps (legacy names — kept as aliases). Phase 4 introduces agent_* canonical
	// twins (registered via agentToolAlias below); both forward to the same
	// LumidOS bridge op, with the canonical name normalized back to app_* before
	// the POST (the schedule server still speaks app_*).
	"app_marketplace": true, "app_detail": true, "app_new": true, "app_templates": true,
	"app_install": true, "app_clone": true, "app_update": true, "app_validate": true,
	"app_list": true, "app_run": true, "app_publish": true, "app_push": true,
	"app_unpublish": true, "app_add_skill": true, "skill_search": true, "loop_metrics": true,
	// Phase 4 canonical agent_* names — accepted by the dispatcher; normalized
	// back to app_* on the wire by agentToolWireName().
	"agent_marketplace": true, "agent_detail": true, "agent_new": true, "agent_templates": true,
	"agent_install": true, "agent_clone": true, "agent_update": true, "agent_validate": true,
	"agent_list": true, "agent_run": true, "agent_publish": true, "agent_push": true,
	"agent_unpublish": true, "agent_add_skill": true,
	// Knowledge
	"xp_status": true, "xp_ask": true, "xp_agents": true, "xp_memories": true,
	"xp_ingest": true, "xp_feedback": true, "xp_new_agent": true, "xp_share": true,
	"xp_pull": true, "xp_clone": true, "xp_subscribe": true, "xp_remotes": true,
	"xp_publish": true, "xp_unpublish": true, "xp_marketplace": true,
	"xp_signals": true, "xp_subscriptions": true, "xp_learn": true,
	// Research
	"list_loops": true, "loop_status": true, "run_loop": true,
	"create_loop": true, "loop_history": true, "squeeze": true,
	"research_publish_workflow": true, "research_workflows": true,
	"research_clone_workflow": true, "research_unpublish_workflow": true,
	// Platform
	"submit_workflow": true, "list_workers": true, "optimize_workflow": true,
}

// agentToolAlias maps each Phase-4 canonical agent_* tool name to the legacy
// app_* name it aliases. Both names are advertised in the tool catalog and both
// dispatch to the same handler; the canonical name is normalized back to the
// legacy wire name before the LumidOS bridge POST (the schedule server still
// recognizes app_* only). Keeping the alias means in-flight clients/prompts
// that call app_* never break.
var agentToolAlias = map[string]string{
	"agent_marketplace": "app_marketplace",
	"agent_detail":      "app_detail",
	"agent_new":         "app_new",
	"agent_templates":   "app_templates",
	"agent_install":     "app_install",
	"agent_clone":       "app_clone",
	"agent_update":      "app_update",
	"agent_validate":    "app_validate",
	"agent_list":        "app_list",
	"agent_run":         "app_run",
	"agent_publish":     "app_publish",
	"agent_push":        "app_push",
	"agent_unpublish":   "app_unpublish",
	"agent_add_skill":   "app_add_skill",
}

// agentToolWireName normalizes a canonical agent_* tool name to the legacy
// app_* name the LumidOS schedule server understands. Non-aliased names pass
// through unchanged.
func agentToolWireName(name string) string {
	if legacy, ok := agentToolAlias[name]; ok {
		return legacy
	}
	return name
}

// lumidosURL returns the base URL of the LumidOS schedule server.
func lumidosURL() string {
	if u := os.Getenv("LUMIDOS_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:9100"
}

// dispatchLumidosTool POSTs to the schedule server's tool bridge and returns
// the result map. The schedule server runs the actual Python ops function.
// tenantSubHeader carries the CALLER's identity to the LumidOS tool server.
//
// Without it LumidOS resolves app bundles against the operator's own ~/.xp and
// finds nothing for a tenant, so every app tool answered "app not found" and
// the agent reported "I don't see any apps installed in your tenant" — for apps
// that were installed, healthy and listed by /me/apps. LumidOS's
// resolve_bundle_dir already searches ~/.tenants/<sub>/.xp when LUMID_TENANT_SUB
// is set; nothing on the wire was telling it which tenant was calling.
const tenantSubHeader = "X-Lumid-Tenant-Sub"

func dispatchLumidosTool(userID, name string, args map[string]any) (map[string]any, bool) {
	payload, _ := json.Marshal(map[string]any{"tool": name, "args": args})
	// 90s: ops tools walk the knowledge graph (xp_status on a large KG
	// measures ~35s) — 30s cut those off mid-flight.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		lumidosURL()+"/api/v1/tools/invoke", bytes.NewReader(payload))
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req.Header.Set(tenantSubHeader, userID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"error": "lumidos unreachable: " + err.Error()}, false
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return map[string]any{"error": "bad response from lumidos"}, false
	}
	ok, _ := out["ok"].(bool)
	return out, ok
}

// ── Per-user workspace root (path jail) ─────────────────────────────────────

// codebaseRoot() lives in admin_codebase_repos.go — the /proj tree as exposed
// inside the container (LUMID_CODEBASE_ROOT, /var/lib/lumid-codebase, or /proj).

// ownWorkspace is the caller's personal tenant workspace —
// /home/<operator>/.tenants/<userID>/ — holding .xp/apps, .xp/kg, .chats,
// etc. EVERY user (gemma4 or any model) has full read+write here; this is
// the single, consistent meaning of "your own workspace".
func ownWorkspace(userID string) string {
	return tenantRoot(userID)
}

// readRoot is where file READS are jailed. admin + super_admin can read the
// whole deployment codebase (/proj) — admin read-only (see writeRoot);
// everyone else is confined to their own tenant workspace. (admin+ also get
// an appBundlePath fallback in toolReadFile to read their own app bundles.)
func readRoot(userID, role string) string {
	switch role {
	case "super_admin", "admin":
		return codebaseRoot()
	default:
		return ownWorkspace(userID)
	}
}

// writeRoot is where WRITES and bash exec are jailed. Only super_admin may
// mutate the deployment codebase (/proj). EVERYONE ELSE — admin included —
// is confined to their OWN tenant workspace and can NEVER touch /proj: that
// is the "admin = read-only on the deployment workspace" guarantee. (Admins
// no longer write into the operator-shared ~/.xp/apps; their writes land in
// their own tenant dir, same as any other user.)
func writeRoot(userID, role string) string {
	switch role {
	case "super_admin":
		return codebaseRoot()
	default:
		return ownWorkspace(userID)
	}
}

// appBundlePath resolves a path that names an installed APP bundle (rather
// than a codebase path) for admin+ callers, so the chatbox agent can read an
// app's files by name when asked to debug it. Searches the operator-shared
// apps dir and the caller's own tenant apps dir — never another tenant's, so
// the workspace-isolation guarantee holds. Returns "" when not applicable.
func appBundlePath(userID, role, rawPath string) string {
	if role != "admin" && role != "super_admin" {
		return ""
	}
	roots := []string{
		filepath.Join(operatorHome(), ".xp", "apps"),
		tenantAppsDir(userID),
	}
	for _, root := range roots {
		if abs, err := jailPath(root, rawPath); err == nil {
			if _, statErr := os.Stat(abs); statErr == nil {
				return abs
			}
		}
	}
	return ""
}

// jailPath resolves rawPath relative to the given root and ensures it cannot
// escape via symlinks or ".." traversal. Callers pick the root (readRoot for
// reads, writeRoot for writes/exec) so a read-only role can't write where it
// can read.
func jailPath(root, rawPath string) (string, error) {
	abs := filepath.Join(root, rawPath)
	abs = filepath.Clean(abs)
	// HasPrefix check needs a trailing separator so "/projfoo" doesn't pass as a
	// subpath of "/proj".
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes workspace")
	}
	return abs, nil
}

// ── File tools ───────────────────────────────────────────────────────────────

func toolReadFile(userID, role, rawPath string) (map[string]any, bool) {
	abs, err := jailPath(readRoot(userID, role), rawPath)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	info, err := os.Stat(abs)
	if err != nil {
		// Fallback: the path may name an INSTALLED APP bundle (which lives
		// under ~/.xp/apps or the caller's tenant, not the /proj codebase).
		// Lets the chatbox agent read an app's xpcloud.yaml / ui / commands
		// by name (e.g. "lumid-gpu-rentals/xpcloud.yaml") when asked about it.
		if alt := appBundlePath(userID, role, rawPath); alt != "" {
			if ai, aerr := os.Stat(alt); aerr == nil {
				abs, info, err = alt, ai, nil
			}
		}
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
	}
	// When a directory is passed, return a listing instead of failing.
	if info.IsDir() {
		entries, err := os.ReadDir(abs)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		lines := make([]string, 0, len(entries))
		var sampleChild string
		for _, e := range entries {
			if e.IsDir() {
				lines = append(lines, e.Name()+"/")
			} else {
				lines = append(lines, e.Name())
				if sampleChild == "" {
					sampleChild = e.Name()
				}
			}
		}
		// Suggest a real child file from this listing rather than a fixed
		// example, so the hint stays valid at any depth.
		hint := "This is a directory. Call read_file again with a specific file path inside it."
		if sampleChild != "" {
			hint = "This is a directory. Call read_file again with a specific file, e.g. '" +
				filepath.ToSlash(filepath.Join(rawPath, sampleChild)) + "'."
		}
		return map[string]any{
			"path":    abs,
			"is_dir":  true,
			"entries": lines,
			"hint":    hint,
		}, true
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// 200 KB (~50K tokens) — the smallest model context in the registry is
	// minimax at 196K, so a single large read no longer needs the old 50 KB
	// cap that was tuned for tighter budgets.
	const maxBytes = 200 * 1024
	truncated := false
	if len(data) > maxBytes {
		data = data[:maxBytes]
		truncated = true
	}
	return map[string]any{
		"content":   string(data),
		"path":      abs,
		"truncated": truncated,
		"size":      len(data),
	}, true
}

func toolWriteFile(userID, role, rawPath, content string) (map[string]any, bool) {
	root := writeRoot(userID, role)
	abs, err := jailPath(root, rawPath)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// Disk quota: 500 MB per user workspace
	if err := checkDiskQuota(root, int64(len(content))); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	return map[string]any{"ok": true, "path": abs, "bytes": len(content)}, true
}

func toolEditFile(userID, role, rawPath, oldStr, newStr string, replaceAll bool) (map[string]any, bool) {
	abs, err := jailPath(writeRoot(userID, role), rawPath)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	original := string(data)
	if !strings.Contains(original, oldStr) {
		return map[string]any{"error": "old_string not found in file"}, false
	}
	n := 1
	updated := strings.Replace(original, oldStr, newStr, 1)
	if replaceAll {
		n = strings.Count(original, oldStr)
		updated = strings.ReplaceAll(original, oldStr, newStr)
	}
	if err := os.WriteFile(abs, []byte(updated), 0o644); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	return map[string]any{"ok": true, "path": abs, "replacements": n}, true
}

// checkDiskQuota estimates usage in root and rejects if adding extraBytes would
// exceed 500 MB. Uses a fast du approximation.
func checkDiskQuota(root string, extraBytes int64) error {
	const limitBytes = 500 * 1024 * 1024
	// Best-effort: walk the directory tree
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	if total+extraBytes > limitBytes {
		return fmt.Errorf("disk quota exceeded (%.1f MB used of 500 MB)", float64(total)/(1024*1024))
	}
	return nil
}

// ── Bash sandbox ─────────────────────────────────────────────────────────────

// bashBlockedPhrases are literal substrings we reject before running any command.
var bashBlockedPhrases = []string{
	":(){ :|:", // fork bomb (catches : (){ :|:& };: and variants)
	"rm -rf /", // destructive rm (catches rm -rf /*)
	"mkfs",
	"dd if=/dev/zero",
	"shutdown",
	"reboot",
}

func toolBashExec(userID, role, command string, timeoutSec int) (map[string]any, bool) {
	if timeoutSec <= 0 || timeoutSec > 120 {
		timeoutSec = 30
	}
	for _, phrase := range bashBlockedPhrases {
		if strings.Contains(command, phrase) {
			return map[string]any{"error": "command blocked by safety policy"}, false
		}
	}

	// Rate limit: 6 executions per user per minute
	if !checkExecRateLimit(userID) {
		return map[string]any{"error": "execution rate limit: max 6 per minute"}, false
	}

	// Per-user concurrency: max 1 concurrent sandbox
	userSlot := make(chan struct{}, 1)
	actual, _ := userSandboxMu.LoadOrStore(userID, userSlot)
	slot := actual.(chan struct{})
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	default:
		return map[string]any{"error": "a sandbox is already running for your session"}, false
	}

	// Global concurrency cap
	select {
	case sandboxSemaphore <- struct{}{}:
		defer func() { <-sandboxSemaphore }()
	default:
		return map[string]any{"error": "sandbox slots full, try again shortly"}, false
	}

	cwd := writeRoot(userID, role)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	if role != "super_admin" {
		// Non-operator: this container has no docker/sandbox runtime (uid
		// 1000, userns disabled), so delegate to the in-cluster
		// claude-sandbox, which runs the command confined to the caller's
		// own workspace — netpol-locked pod, prlimit-fenced process.
		return bashViaSandboxBroker(ctx, userID, command, timeoutSec)
	}

	// super_admin (operator): run in this container's process space against
	// the codebase tree. Alpine ships /bin/sh, not bash — prefer bash when
	// present, fall back to sh.
	shell := "bash"
	if _, err := exec.LookPath("bash"); err != nil {
		shell = "sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-c", command)
	cmd.Dir = cwd

	out, err := cmd.CombinedOutput()
	if len(out) > 100*1024 {
		out = out[:100*1024]
	}
	if err != nil {
		exitCode := -1
		if ctx.Err() == context.DeadlineExceeded {
			return map[string]any{"error": "timed out", "output": string(out)}, false
		}
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
			if exitCode == 137 {
				return map[string]any{"error": "sandbox killed (out of memory)", "output": string(out)}, false
			}
		}
		return map[string]any{"error": err.Error(), "exit_code": exitCode, "output": string(out)}, false
	}
	return map[string]any{"output": string(out), "exit_code": 0}, true
}

// bashViaSandboxBroker runs a non-super bash command on the in-cluster
// claude-sandbox (/sandbox/bash). The sandbox derives the workspace from
// user_id itself (client paths are never trusted) and confines execution
// there — netpol-locked pod, prlimit-fenced process. Returns the same
// {output, exit_code} shape as the in-container operator path.
func bashViaSandboxBroker(ctx context.Context, userID, command string, timeoutSec int) (map[string]any, bool) {
	payload, _ := json.Marshal(map[string]any{
		"user_id": userID,
		"command": command,
		"timeout": timeoutSec,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		claudeSandboxURL()+"/sandbox/bash", bytes.NewReader(payload))
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", os.Getenv("LUMID_IDENTITY_BRIDGE_SECRET"))
	client := &http.Client{Timeout: time.Duration(timeoutSec+10) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"error": "sandbox broker unreachable: " + err.Error()}, false
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return map[string]any{"error": "sandbox broker bad response: " + err.Error()}, false
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = fmt.Sprintf("broker HTTP %d", resp.StatusCode)
		}
		return map[string]any{"error": "sandbox: " + msg}, false
	}
	if e, _ := out["error"].(string); e != "" {
		return out, false
	}
	ec, _ := out["exit_code"].(float64)
	return out, ec == 0
}

func checkExecRateLimit(userID string) bool {
	userExecRateMu.Lock()
	defer userExecRateMu.Unlock()
	now := time.Now().Unix()
	ts := userExecCounts[userID]
	// Keep only entries within the last 60 seconds
	filtered := ts[:0]
	for _, t := range ts {
		if now-t < 60 {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= 6 {
		userExecCounts[userID] = filtered
		return false
	}
	userExecCounts[userID] = append(filtered, now)
	return true
}

// ── Approval gate ─────────────────────────────────────────────────────────────
// For destructive tools: emit tool_approval_required SSE, then block until
// the user approves or 30 s pass. The approval is delivered via a separate
// HTTP endpoint (MeAgentToolApprove).

// requestApproval registers a pending approval and returns the channel.
// The caller must call emit before reading from the channel.
func requestApproval(approvalID string) chan bool {
	ch := make(chan bool, 1)
	toolApprovals.Store(approvalID, ch)
	return ch
}

// MeAgentToolApprove — POST /api/v1/me/agent/chat/tool-approve
// Body: {"approval_id": "...", "approved": true, "always": false, "tool": ""}
// Unblocks the pending tool dispatch in the SSE stream. When always=true
// (and approved), the named tool is added to the caller's persistent
// grant list — future calls skip the approval gate entirely. Grants are
// per-user and revocable via DELETE /me/agent/tool-grants/:name.
func MeAgentToolApprove(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		ApprovalID string `json:"approval_id"`
		Approved   bool   `json:"approved"`
		Always     bool   `json:"always,omitempty"`
		Tool       string `json:"tool,omitempty"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ApprovalID == "" {
		fail(c, http.StatusBadRequest, 1400, "approval_id required")
		return
	}
	// LoadAndDelete is atomic — two concurrent approve POSTs for the same id
	// can't both Load-then-send (which would block the second forever on the
	// cap-1 channel and leak a goroutine). The loser gets the 404 below.
	ch, ok := toolApprovals.LoadAndDelete(body.ApprovalID)
	if !ok {
		fail(c, http.StatusNotFound, 1404, "approval not found (may have timed out)")
		return
	}
	if body.Approved && body.Always && destructiveTools[body.Tool] {
		_ = grantTool(userID, body.Tool)
	}
	// Non-blocking send: if the waiting stream already gave up (10-min timeout
	// or client disconnect), there's no reader — don't block this request.
	select {
	case ch.(chan bool) <- body.Approved:
	default:
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// llmProvider describes an upstream LLM endpoint that speaks
// Anthropic's /v1/messages wire format (including streaming SSE
// events). New options just need an entry here — the tool-use loop
// + stream parser don't change.
type llmProvider struct {
	id            string // stable id passed from the frontend
	displayName   string // human label (e.g. "Claude Haiku 4.5")
	endpoint      string // upstream URL
	upstreamModel string // the model name sent to the upstream API
	authHeader    string // "x-api-key" (Anthropic) | "Authorization" (kv.run)
	authPrefix    string // "" (Anthropic) | "Bearer " (kv.run)
	keyFn         func() (string, error)
	// addAnthropicVersion — Anthropic's API needs the "anthropic-version"
	// header; kv.run's /v1/messages does not. Set to true for Anthropic.
	addAnthropicVersion bool
	// supportsVision — can read `image` content blocks. gemma4 (verified
	// through the kv.run gateway) + Anthropic do; MiniMax is text-only.
	supportsVision bool
	// minRole — minimum role allowed to SELECT this provider in the panel.
	// "" / "user" = everyone; "admin"; "super_admin". Policy: gemma4 for
	// all, minimax for admin+, claude (Anthropic) for super_admin only.
	minRole string
	// maxOutputTokens — per-turn output cap (the `max_tokens` field). 0 →
	// the global maxTokensPerTurn default. The in-cluster GPU models have
	// huge context (gemma4 262K, minimax 196K — verified via
	// GET kv.run:5000/v1/models) and no per-call charge, so they get a far
	// larger budget than the cost-bounded Anthropic default. A too-small cap
	// is the main cause of truncated structured output (JSON/YAML cut mid-doc).
	maxOutputTokens int
	// dailyBudgetTokens — per-user 24h cap for THIS provider, in input+output
	// tokens. 0 → the global dailyTokenBudget() default; <0 → no cap. Local
	// GPU models are free at the margin, so they carry a generous backstop
	// rather than the tight Anthropic-cost default.
	dailyBudgetTokens int
}

// First entry is the default (defaultProvider() returns llmProviders[0]).
// Order: in-cluster GPU first (no per-call API charge to Anthropic, the
// fleet is already paid for), Anthropic as the hosted fallback.
var llmProviders = []llmProvider{
	{
		// gemma4 — default. Served by the in-cluster lumid-llm gateway
		// (LUMID_LLM_BASE, default http://lumid-llm:8088), which speaks the
		// Anthropic /v1/messages API incl. SSE. Model id from
		// GET lum.id/llm/v1/models. Reasoning model (emits thinking deltas,
		// handled by the SSE parser). The old kv.run:5000 endpoint is dead.
		id:                  "kvrun-gemma4",
		displayName:         "Gemma-4-26B-A4B (Lumid GPU)",
		endpoint:            lumidLLMBase() + "/v1/messages",
		upstreamModel:       "nvidia/Gemma-4-26B-A4B-NVFP4",
		authHeader:          "Authorization",
		authPrefix:          "Bearer ",
		keyFn:               kvrunPAT,
		addAnthropicVersion: false,
		supportsVision:      true,   // multimodal; image blocks verified via lumid-llm
		minRole:             "user", // everyone
		maxOutputTokens:     16384,  // 262K ctx, free local GPU — let answers/structured output run
		dailyBudgetTokens:   -1,     // free local GPU; the 6000/min gateway rate-limit is the abuse guard
	},
	{
		// qwen3.6-35b-a3b — MoE (35B/A3B), vision-capable, 262K context.
		// Served by lumid-llm (luyao1 GPU1, llama.cpp). Strong general model.
		id:                  "lumid-qwen3-35b",
		displayName:         "Qwen3.6-35B-A3B (Lumid GPU)",
		endpoint:            lumidLLMBase() + "/v1/messages",
		upstreamModel:       "qwen3.6-35b-a3b",
		authHeader:          "Authorization",
		authPrefix:          "Bearer ",
		keyFn:               kvrunPAT,
		addAnthropicVersion: false,
		supportsVision:      true,   // mmproj vision on luyao1 GPU1
		minRole:             "user", // everyone — free local GPU
		maxOutputTokens:     16384,  // 262K ctx
		dailyBudgetTokens:   -1,
	},
	{
		// qwen3.6-27b — dense 27B, vision-capable, 32K context.
		// Served by lumid-llm (luyao1 GPU0, llama.cpp).
		id:                  "lumid-qwen3-27b",
		displayName:         "Qwen3.6-27B (Lumid GPU)",
		endpoint:            lumidLLMBase() + "/v1/messages",
		upstreamModel:       "qwen3.6-27b",
		authHeader:          "Authorization",
		authPrefix:          "Bearer ",
		keyFn:               kvrunPAT,
		addAnthropicVersion: false,
		supportsVision:      true,   // both luyao1 models are vision-capable
		minRole:             "user", // everyone — free local GPU
		maxOutputTokens:     8192,   // 32K ctx — smaller output budget
		dailyBudgetTokens:   -1,
	},
	// claude-code-* — real Claude Code sessions in the in-cluster
	// claude-sandbox, model access through the POOLED account proxy with a
	// per-user ephemeral PAT. minRole mirrors the pool's own model matrix
	// (user→sonnet, admin→+opus, super_admin→+fable) and the pool's 5h/7d
	// per-user quota is the SINGLE limiter — dailyBudgetTokens -1 here so
	// identity's daily budget doesn't double-count the same tokens.
	{
		id:                "claude-code-sonnet",
		displayName:       "Claude Sonnet (Code)",
		endpoint:          "",       // no HTTP endpoint — subprocess via sandbox
		upstreamModel:     "sonnet", // claude CLI --model alias
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "user", // pool allows user→sonnet; pool quota gates volume
		dailyBudgetTokens: -1,
	},
	{
		id:                "claude-code-opus",
		displayName:       "Claude Opus (Code)",
		endpoint:          "",
		upstreamModel:     "opus", // claude CLI --model alias
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "admin", // pool: opus = admin+
		dailyBudgetTokens: -1,
	},
	{
		id:                "claude-code-fable",
		displayName:       "Claude Fable 5 (Code)",
		endpoint:          "",
		upstreamModel:     "claude-fable-5", // full id — CLI has no fable alias
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "super_admin", // pool: fable = super_admin only
		dailyBudgetTokens: -1,
	},
	// External models through the pool proxy's OpenAI-compat path (separate
	// API keys — no Anthropic pool 5h/7d consumption, but metered per-user
	// with real cost + recorded on /claude-sessions). The proxy itself gates
	// these admin+ by the PAT's role; minRole mirrors that.
	{
		id:                "claude-code-kimi",
		displayName:       "Kimi K3 (Code)",
		endpoint:          "",
		upstreamModel:     "kimi-k3", // Moonshot via pool proxy oaicompat
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "admin",
		dailyBudgetTokens: -1,
	},
	{
		id:                "claude-code-glm",
		displayName:       "GLM-5.2 (Code)",
		endpoint:          "",
		upstreamModel:     "z-ai/glm-5.2", // OpenRouter via pool proxy oaicompat
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "admin",
		dailyBudgetTokens: -1,
	},
	{
		// Claude Code HARNESS on our own GPU — the sandbox routes the CLI at
		// the lumid-llm gateway ("lumid-llm/<model>" prefix) instead of the
		// pool. Full agentic loop (Bash/Edit/Todo in the user's workspace),
		// zero Anthropic quota, free at the margin. qwen3.6-35b is the only
		// in-house model with workable multi-turn tool calling; gemma-class
		// models struggle in agentic loops, so no gemma entry.
		id:                "claude-code-qwen35",
		displayName:       "Qwen3.6-35B (Code · Lumid GPU)",
		endpoint:          "",
		upstreamModel:     "lumid-llm/qwen3.6-35b-a3b",
		authHeader:        "",
		authPrefix:        "",
		keyFn:             claudeCodeKeyFn,
		supportsVision:    false,
		minRole:           "user",
		dailyBudgetTokens: -1,
	},
	// claude-opus and claude-haiku (direct Anthropic API) are registered only
	// when ANTHROPIC_API_KEY is set. Without it they 503 immediately.
	// The claude-code-* sandbox providers cover Anthropic models instead.
}

// roleRank ranks the role hierarchy for provider gating.
func roleRank(role string) int {
	switch role {
	case "super_admin":
		return 2
	case "admin":
		return 1
	default:
		return 0 // user / unknown
	}
}

// providerAllowed reports whether a caller of the given role may select p.
func providerAllowed(userRole string, p llmProvider) bool {
	return roleRank(userRole) >= roleRank(p.minRole)
}

// currentUserRole resolves the caller's role from the JWT claim, falling
// back to a DB lookup for PAT-authed callers (whose token carries no role).
// Defaults to "user" so gating fails closed to the least privilege.
func currentUserRole(c *gin.Context) string {
	if tok := bearerToken(c); tok != "" {
		if claims, err := common.VerifyJWT(tok); err == nil && claims.Role != "" {
			return claims.Role
		}
	}
	if uid, ok := currentUserID(c); ok {
		var u models.User
		if err := common.DB.Select("role").Where("id = ?", uid).First(&u).Error; err == nil && u.Role != "" {
			return u.Role
		}
	}
	return "user"
}

// defaultProviderFor returns the preferred provider for the caller's role.
// super_admin defaults to claude-code-sonnet (Claude Code subscription — conserves
// the Opus quota per operator preference; Opus stays selectable in the picker);
// everyone else gets gemma4 (in-cluster GPU, no per-call cost).
func defaultProviderFor(role string) llmProvider {
	if role == "super_admin" {
		for _, p := range llmProviders {
			if p.id == "claude-code-sonnet" {
				return p
			}
		}
	}
	for _, p := range llmProviders {
		if providerAllowed(role, p) {
			return p
		}
	}
	return defaultProvider()
}

func defaultProvider() llmProvider { return llmProviders[0] }

// MeAgentModels — GET /api/v1/me/agent/models.
// Lists the LLM backends StudioChat can target. Public-shape only —
// no keys, no endpoints. Reflects the llmProviders registry; new
// entries auto-surface in the UI dropdown without frontend changes.
func MeAgentModels(c *gin.Context) {
	// Require auth — the model catalog is role-dependent and shouldn't be
	// served to anonymous callers (it previously returned 200 to no token).
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	type item struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Default     bool   `json:"default"`
		// AppTools — does this model get identity's tool catalog (casebook,
		// app_answer, review_action, …)? The claude-code path delegates to the
		// sandbox runner and is handed NO tools, so an app's data and scoring
		// are simply unreachable there. Picking such a model inside an app
		// silently changes what the app can do, which reads as the app being
		// broken. Reported as a capability so the UI can warn rather than
		// name-matching "claude-code" in the frontend.
		AppTools bool `json:"app_tools"`
	}
	role := currentUserRole(c)
	out := make([]item, 0, len(llmProviders))
	def := defaultProviderFor(role).id
	for _, p := range llmProviders {
		if !providerAllowed(role, p) {
			continue // policy: hide providers above the caller's role
		}
		out = append(out, item{ID: p.id, DisplayName: p.displayName, Default: p.id == def, AppTools: !isClaudeCodeProvider(p)})
	}
	c.JSON(http.StatusOK, gin.H{"models": out})
}

// providerSupportsVision returns true for providers that can read
// `image` content blocks. Only Anthropic-shape endpoints in our
// registry today — kv.run/MiniMax-M2.7 is text-only ("is not a
// multimodal model" error from the upstream). If we add new
// providers later, gate on this flag rather than ad-hoc matching.
func providerSupportsVision(p llmProvider) bool {
	return p.supportsVision
}

// containsImageAttachment scans every message in the request for an
// image attachment. Used to auto-route to a vision-capable provider
// when the user's selected model can't read images.
func containsImageAttachment(msgs []chatMessage) bool {
	for _, m := range msgs {
		for _, a := range m.Attachments {
			if a.Kind == "image" {
				return true
			}
		}
	}
	return false
}

// autoRouteForTurn — if the resolved provider can't handle the
// content in the current request, override to claude-haiku (the only
// vision-capable provider today). Returns (provider, autoRouted)
// where autoRouted is true when we overrode. Used to surface the
// override in the usage event so the UI can show "answered by
// Claude (auto)" instead of pretending the user's selection ran.
func autoRouteForTurn(req []chatMessage, picked llmProvider, role string, ctx map[string]any, mode string) (llmProvider, bool) {
	if containsImageAttachment(req) && !providerSupportsVision(picked) {
		// Route to the first vision-capable provider the caller's role
		// allows. gemma4 is first + allowed to everyone + multimodal, so
		// this lands on gemma4 for all roles (no policy escalation).
		for _, p := range llmProviders {
			if providerSupportsVision(p) && providerAllowed(role, p) {
				return p, true
			}
		}
	}
	// The claude-code CLI provider runs its OWN toolset (Bash/Read/Write/Web) and
	// can't see the me_agent registry, so any turn that NEEDS those tools must
	// route to a tool-capable (HTTP /v1/messages) provider. Two such turns:
	//   • a grounded observability drill-in (cycle/step/case → cycle_detail,
	//     casebook, … data tools), or
	//   • a control-plane request (install/run/publish/edit-ui/promote/… — the
	//     verbs the PLATFORM is driven by, served by the me_agent tools).
	// This is what makes "controllability work for ALL models": select Claude
	// Code, ask it to install/run/publish/edit something, and the action still
	// executes — on a tool-capable model, surfaced via the `route` event. (We
	// only steal clearly-platform turns; generic "run the tests / install numpy"
	// stay in claude-code, where its Bash/file tools are the right runtime.)
	//   • an explicit Search / Deep-research toggle (mode) — those are served
	//     by the Tavily-backed me_agent tools, and the sandbox's NetworkPolicy
	//     blocks the CLI's own WebSearch/WebFetch anyway, so staying in
	//     claude-code made the toggle a silent no-op.
	if isClaudeCodeProvider(picked) &&
		(groundedDrillIn(ctx) || controlIntent(req) || mode == "search" || mode == "deep_research") {
		if p, ok := firstToolCapableProvider(role); ok {
			return p, true
		}
	}
	return picked, false
}

// firstToolCapableProvider returns the best non-claude-code provider the role
// may use — these speak Anthropic /v1/messages and so expose the full me_agent
// tool registry + run the tool-use loop. Prefers kvrun-minimax for tool-
// following quality, else the first allowed provider (gemma4 for everyone).
func firstToolCapableProvider(role string) (llmProvider, bool) {
	var fallback *llmProvider
	for i := range llmProviders {
		p := llmProviders[i]
		if isClaudeCodeProvider(p) || !providerAllowed(role, p) {
			continue
		}
		if fallback == nil {
			fallback = &p
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return llmProvider{}, false
}

// controlIntent reports whether the latest user turn asks the assistant to DO
// something on the PLATFORM (install/run/publish/edit/promote/…) — work that
// needs the me_agent control-plane tools. Heuristic (recall-biased, but kept to
// clearly-platform phrases so it doesn't steal shell/code turns from claude-
// code): a hit routes a tool-less provider to a tool-capable one; a miss simply
// behaves as before. Scans only the most recent user message.
func controlIntent(msgs []chatMessage) bool {
	text := ""
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			text = strings.ToLower(msgs[i].Content)
			break
		}
	}
	if text == "" {
		return false
	}
	for _, kw := range controlIntentPhrases {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

// controlIntentPhrases — platform-control cues. Deliberately phrase-level (e.g.
// "run the workflow", not bare "run ") so code/shell asks a super_admin uses
// claude-code for ("run the tests", "install numpy") are NOT routed away.
var controlIntentPhrases = []string{
	// app lifecycle
	"install the app", "install app", "uninstall", "reinstall the app",
	"remove the app", "delete the app",
	"fork the app", "fork this app", "publish the app", "publish this app",
	"publish my app", "unpublish", "propose upstream", "open a pr upstream",
	"subscribe to", "add the skill", "add skill to", "import the skill",
	// run / schedule a workflow (platform nouns, not bare "run")
	"run the workflow", "run this workflow", "run the loop", "run the app",
	"run the cycle", "run a cycle", "run now", "run it now", "trigger the workflow",
	"trigger the loop", "kick off the", "fire the workflow", "fire a run",
	"pause the workflow", "pause this workflow", "resume the workflow",
	"pause the loop", "resume the loop", "stop the workflow",
	"schedule the workflow", "schedule this workflow", "schedule the loop",
	"change the schedule", "set the schedule", "set the cron",
	// runs
	"promote the run", "promote this run", "promote run", "discard the run",
	"discard this run", "discard run",
	// app surface / config authoring
	"edit the app ui", "edit the page", "edit the ui", "edit the config",
	"edit the app config", "update the config", "update the app config",
	"generate a ui", "generate the ui", "generate a page", "generate the page",
	"regenerate the page", "build the page", "build me a page",
	// authoring / composition
	"create a workflow", "new workflow", "create an app", "new app", "compose a workflow",
	// trading / quantarena
	"place a trade", "register the strategy", "register a strategy",
	"join the competition", "join competition",
	// account / admin
	"set my profile", "remember that i", "set the role", "set user role",
	"grant access", "suspend the user", "suspend user",
}

// groundedDrillIn reports whether the turn's viewing context points at a
// specific run / step / case (vs a bare app-level view) — i.e. a question
// that needs the me_agent observability tools to answer.
func groundedDrillIn(ctx map[string]any) bool {
	if ctx == nil {
		return false
	}
	for _, k := range []string{"cycle", "step_id", "case_id"} {
		if v, ok := ctx[k]; ok && v != nil && v != "" {
			return true
		}
	}
	return false
}

// resolveProvider picks the provider for a chat request. Falls back
// to the default (Claude) on empty or unrecognized model strings so
// clients that don't pass `model` keep working.
func resolveProvider(modelID, role string) llmProvider {
	if modelID != "" {
		for _, p := range llmProviders {
			if p.id == modelID {
				if providerAllowed(role, p) {
					return p
				}
				// Requested a provider above the caller's role → fall back
				// to their default (gemma4) rather than 403, so the panel
				// degrades gracefully if a stale id is sent.
				return defaultProviderFor(role)
			}
		}
	}
	return defaultProviderFor(role)
}

type chatMessage struct {
	Role    string `json:"role"`              // "user" | "assistant"
	Content string `json:"content,omitempty"` // for the simple text-only frontend
	// content_blocks (Anthropic's structured form) is what we use
	// internally during the tool-use loop. The frontend sends only
	// flat `content` text; we promote to blocks server-side.
	//
	// Optional file attachments — the chat footer's paperclip lets
	// users drop images + small text files into a turn. Images turn
	// into an Anthropic `image` content block (Claude vision); text
	// files are inlined as a fenced code block in front of the user
	// text so the LLM sees them as context.
	Attachments []chatAttachment `json:"attachments,omitempty"`
}

// chatAttachment — one file the user dropped into the chat input.
//
//   - kind=image:    Mime + DataB64. Anthropic source.media_type expects
//     "image/png" | "image/jpeg" | "image/gif" | "image/webp".
//   - kind=text:     Text carries the raw content (txt, md, csv, json, yaml,
//     log, etc — anything the frontend can read as a string).
//   - kind=document: Mime + DataB64 for binary documents. Server routes
//     by Mime through extractDocumentText():
//     application/pdf                   → pdftotext
//     application/vnd.openxmlformats-...
//     .wordprocess  → pandoc (docx)
//     application/vnd.openxmlformats-...
//     .spreadsheet  → openpyxl (xlsx)
//     application/vnd.openxmlformats-...
//     .presentation → pandoc (pptx)
//     application/rtf, application/vnd.oasis.opendocument.*,
//     application/epub+zip              → pandoc
//     On Claude (Anthropic) provider, PDFs ship as a native
//     `document` content block instead of going through
//     extraction — preserves tables, layout, embedded images.
type chatAttachment struct {
	Kind    string `json:"kind"`               // "image" | "text" | "document"
	Name    string `json:"name,omitempty"`     // filename hint
	Mime    string `json:"mime,omitempty"`     // image + document
	DataB64 string `json:"data_b64,omitempty"` // image + document — base64-encoded bytes
	Text    string `json:"text,omitempty"`     // text-files only — raw content
}

type meAgentChatBody struct {
	Messages []chatMessage `json:"messages" binding:"required"`
	// Optional: id from llmProviders. Empty → default (Claude).
	Model string `json:"model,omitempty"`
	// Optional UI hint: "search" | "deep_research" | "".
	// When set, an extra line is appended to the system prompt asking
	// the agent to call the matching tool for this turn. The agent
	// can still skip if the question genuinely doesn't need search,
	// but the strong nudge mirrors what ChatGPT/Claude do with their
	// "Search" buttons.
	Mode string `json:"mode,omitempty"`
	// Independent toggle: enable extended thinking on Anthropic
	// providers (Claude shows its reasoning before the answer).
	// kv.run/MiniMax always emits thinking deltas by default; this
	// flag is a no-op there. Combinable with Mode.
	Think bool `json:"think,omitempty"`
	// Optional: id of an installed xpio agent. When set,
	// buildSystemPrompt swaps the me-prefs context for that agent's
	// most-recent bank entries; the chat acts as that agent's
	// spokesperson. See me_agent_agents.go.
	AgentID string `json:"agent_id,omitempty"`
	// Optional: id of a user-defined persona. When set, the persona's
	// system_prompt REPLACES the LumidOS assistant base, allowed_tools[]
	// filters the tool catalog, and preferred_model overrides the
	// picker if no explicit model was passed. Mutually exclusive with
	// agent_id — persona_id wins when both are set. See
	// me_agent_personas.go.
	PersonaID string `json:"persona_id,omitempty"`
	// Optional: claude CLI session id from a previous turn's
	// claude_session SSE event. When set (and owned by this user — see
	// userOwnsClaudeSession), the claude-code provider resumes that
	// session via `claude --resume` instead of replaying flattened
	// history, preserving the CLI's own tool-result context across turns.
	ClaudeSessionID string `json:"claude_session_id,omitempty"`
	// Optional working-context scope (like picking a git repo) — which xpio repo
	// / FlowMesh cluster / lumid-data app the LumidOS MCP tools default to. Threaded
	// to the sandbox → .mcp.json env (claude-code provider only). All optional.
	XpioRepo  string `json:"xpio_repo,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	DataApp   string `json:"data_app,omitempty"`
	// Optional: require a specific tool for THIS turn.
	//
	// Some turns are not the model's judgement call. When the user has picked a
	// case in an app workspace, "answer it as this app's analyst" is already
	// decided — leaving it to tool selection is how a free-form question ends up
	// answered by the generic assistant while the app, its rubric and its
	// grounded/ungrounded distinction sit unused. Neither gemma nor Sonnet
	// selects app_answer unprompted, and four rounds of description-tuning did
	// not move it, so the UI needs a way to say "use this one" rather than ask.
	//
	// Names an allowlisted tool the caller already has; it cannot widen access.
	ToolChoice string `json:"tool_choice,omitempty"`
	// Optional structured "what the user is looking at" payload from the
	// Studio shell (ViewingContext in StudioContext.ts). Rendered into a
	// per-request system block + tool grounding hints so "this run" /
	// "this app" resolve without the user re-stating them. Shape:
	//   {path, page, app?, loop?, run_id?, cycle?{app,loop,ts},
	//    selection?{kind,id,label,affordances[],meta},
	//    picked?{kind,id,label,affordances[]}}
	// Sent fresh each turn (not embedded in history), so it never goes
	// stale on replay.
	Context map[string]any `json:"context,omitempty"`
}

// thinkingBudgetTokens — Anthropic's extended thinking budget. Pulled
// out so we can adjust per-provider later if needed. Must leave room
// in max_tokens for the actual response.
const thinkingBudgetTokens = 8192
const thinkingMaxTokens = 24576 // max_tokens when thinking is enabled (budget + room for the answer)

// chatMessageToAnthropic promotes one chatMessage into the Anthropic
// /v1/messages content shape. With no attachments it stays as a plain
// `content: "<text>"`. With attachments it becomes a list of content
// blocks — text-files inlined as fenced code, images as image blocks,
// PDFs as document blocks (Claude) or pdftotext-extracted fenced
// text (non-Claude providers).
// Returns the {role, content} map suitable for direct append.
func chatMessageToAnthropic(m chatMessage, provider llmProvider) map[string]any {
	if len(m.Attachments) == 0 {
		return map[string]any{"role": m.Role, "content": m.Content}
	}
	blocks := make([]map[string]any, 0, len(m.Attachments)+1)
	for _, a := range m.Attachments {
		switch a.Kind {
		case "image":
			if a.DataB64 == "" || a.Mime == "" {
				continue
			}
			blocks = append(blocks, map[string]any{
				"type": "image",
				"source": map[string]any{
					"type":       "base64",
					"media_type": a.Mime,
					"data":       a.DataB64,
				},
			})
		case "document":
			if a.DataB64 == "" {
				continue
			}
			name := a.Name
			if name == "" {
				name = "document"
			}
			// Claude path + PDF: ship as a native document content
			// block. Preserves layout, tables, and embedded images
			// for vision. Other doc formats still go through text
			// extraction even on Claude.
			if provider.addAnthropicVersion && a.Mime == "application/pdf" {
				blocks = append(blocks, map[string]any{
					"type": "document",
					"source": map[string]any{
						"type":       "base64",
						"media_type": "application/pdf",
						"data":       a.DataB64,
					},
					"title": name,
				})
				continue
			}
			// Everything else: server-side text extraction routed by mime.
			text, extractor, err := extractDocumentText(a.Mime, a.DataB64)
			if err != nil {
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": "Attached document `" + name + "` (" + a.Mime + ") — extraction failed: " + err.Error(),
				})
				continue
			}
			blocks = append(blocks, map[string]any{
				"type": "text",
				"text": "Attached document `" + name + "` (extracted via " + extractor + "):\n```\n" + text + "\n```",
			})
		case "text":
			if a.Text == "" {
				continue
			}
			name := a.Name
			if name == "" {
				name = "attachment"
			}
			fence := "```\n"
			blocks = append(blocks, map[string]any{
				"type": "text",
				"text": "Attached file `" + name + "`:\n" + fence + a.Text + "\n```",
			})
		}
	}
	if m.Content != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
	}
	// If every block is plain text (extracted documents / inlined text files,
	// no image or document-source block), collapse to a single STRING content.
	// The lumid-llm `/v1/messages` shim (and OpenAI-compat upstreams generally)
	// IGNORE block-ARRAY content and return an empty 0-token completion — so a
	// document attachment silently produced no output. Flattening keeps the
	// extracted text visible to every provider; the structured array is kept
	// only when a real image/document block needs it (Anthropic vision).
	allText := true
	for _, b := range blocks {
		if t, _ := b["type"].(string); t != "text" {
			allText = false
			break
		}
	}
	if allText {
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if s, ok := b["text"].(string); ok {
				parts = append(parts, s)
			}
		}
		return map[string]any{"role": m.Role, "content": strings.Join(parts, "\n\n")}
	}
	return map[string]any{"role": m.Role, "content": blocks}
}

// modeSystemSuffix returns the line to append to the system prompt
// when the user has flipped a tool-forcing toggle in the chat UI.
// Empty string for "" / unknown modes (no-op).
func modeSystemSuffix(mode string) string {
	citationRules := "\n\nCITATIONS: cite every fact that came from a web tool using GitHub-flavored markdown footnotes. This is mandatory — a reply with sourced facts and no inline citations is broken. EXACT SHAPE:\n\n  The S&P 500 closed at 6420 yesterday[^1], up 0.4% on the week[^2].\n\n  [^1]: https://example.com/markets-page\n  [^2]: https://other.com/weekly-recap\n\nRules:\n- One `[^n]` marker per claim, attached without a space to the word it cites.\n- Define every `[^n]` you reference at the very end of the reply, one per line.\n- URLs verbatim from the tool — never paraphrase or invent.\n- Reuse the same number for repeated sources; don't duplicate definitions.\n- Skip footnotes entirely only if you didn't actually use a source.\n- Do NOT add a `## Sources` heading — the frontend builds the footnotes block automatically from the `[^n]:` definitions."
	switch mode {
	case "search":
		return "\n\nFor this turn, the user has explicitly enabled web search. Call the `web_search` tool to ground your answer in current web sources before replying. If the question is purely about the user's own knowledge or tenant state and search would be irrelevant, you may skip it — but err on the side of searching." + citationRules
	case "deep_research":
		return "\n\nFor this turn, the user has explicitly enabled deep research. Call the `deep_research` tool with a focused question derived from the user's message, then synthesize a brief from the returned sources." + citationRules
	}
	return ""
}

type toolCallResult struct {
	Name   string         `json:"name"`
	Args   map[string]any `json:"args"`
	Result map[string]any `json:"result"`
	OK     bool           `json:"ok"`
}

// POST /api/v1/me/agent/chat
// ctxModeKey carries the validated interview mode from the handler to
// dispatchTool, which has no access to the request body. Stashed rather than
// threaded through every tool signature — only the judge needs it, and only to
// decide whether MISSED keypoints may be returned.
const ctxModeKey = "lumid_interview_mode"

func MeAgentChat(c *gin.Context) {
	// Stamped BEFORE the turn runs so the recorded cycle's run_ts is when the
	// user asked, not when the model finished — a 40s answer would otherwise
	// place the cycle after events it actually preceded.
	turnStartedAt := time.Now()
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body meAgentChatBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	c.Set(ctxModeKey, chatMode(body.Context))
	stashViewingApp(c, body.Context)
	if len(body.Messages) == 0 {
		fail(c, http.StatusBadRequest, 1400, "messages required")
		return
	}
	if len(body.Messages) > 50 {
		fail(c, http.StatusBadRequest, 1400, "history too long (>50 turns)")
		return
	}

	role := currentUserRole(c)
	provider := resolveProvider(body.Model, role)
	provider, autoRouted := autoRouteForTurn(body.Messages, provider, role, body.Context, body.Mode)
	_ = autoRouted // surfaced via usage event in the stream handler; non-streaming response also signals via the model field below.
	apiKey, err := provider.keyFn()
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503,
			"chat unavailable: "+err.Error())
		return
	}

	// Daily token budget — server-funded LLM. Default 50K total
	// tokens/24h/user. Override via ANTHROPIC_DAILY_TOKEN_BUDGET env.
	// super_admin (operator) is exempt — they run/test the whole platform,
	// not a budgeted end user (the long-standing intent in this comment that
	// was never actually wired).
	budget := effectiveDailyBudget(provider)
	if budget > 0 && role != "super_admin" {
		used := tokensUsedLast24h(userID)
		if used >= budget {
			c.Header("X-Budget-Used", strconv.Itoa(used))
			c.Header("X-Budget-Limit", strconv.Itoa(budget))
			c.Header("X-Budget-Reset", time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))
			fail(c, http.StatusTooManyRequests, 1429,
				fmt.Sprintf("daily chat budget exhausted (%d / %d tokens used in last 24h)", used, budget))
			return
		}
	}

	// Build Anthropic-format messages from the simple frontend shape.
	// Tool-use loop will append assistant + tool_result turns into this
	// list as it iterates.
	anthMsgs := make([]map[string]any, 0, len(body.Messages))
	for _, m := range body.Messages {
		anthMsgs = append(anthMsgs, chatMessageToAnthropic(m, provider))
	}

	basePrompt, tools, _ := resolvePromptAndTools(userID, role, body, true)
	systemPrompt := basePrompt + modeSystemSuffix(body.Mode)
	toolCalls := []toolCallResult{}
	totalInputTokens := 0
	totalOutputTokens := 0
	finalText := ""

	// claude-code-* has no HTTP endpoint — it runs the local claude CLI
	// via the host proxy, which only speaks the streaming NDJSON protocol.
	// Reuse that path with a collecting emit callback so the non-streaming
	// endpoint returns the same {reply, tool_calls, ...} shape. (Without
	// this, callLLM would POST to an empty URL → "unsupported protocol
	// scheme".)
	if isClaudeCodeProvider(provider) {
		ccCtx, ccCancel := context.WithCancel(c.Request.Context())
		defer ccCancel()
		var sb strings.Builder
		argsByID := map[string]map[string]any{}
		var streamErr string
		var ccSessionID string
		emit := func(ev map[string]any) bool {
			switch ev["type"] {
			case "claude_session":
				if sid, ok := ev["session_id"].(string); ok {
					ccSessionID = sid
				}
			case "text":
				if d, ok := ev["delta"].(string); ok {
					sb.WriteString(d)
				}
			case "tool_start":
				id, _ := ev["id"].(string)
				if a, ok := ev["args"].(map[string]any); ok {
					argsByID[id] = a
				}
			case "tool_call":
				id, _ := ev["id"].(string)
				name, _ := ev["name"].(string)
				okv, _ := ev["ok"].(bool)
				// Claude Code tool results arrive as string or list content,
				// not the map[string]any our struct expects — wrap uniformly.
				res, isMap := ev["result"].(map[string]any)
				if !isMap {
					res = map[string]any{"content": ev["result"]}
				}
				toolCalls = append(toolCalls, toolCallResult{
					Name:   name,
					Args:   argsByID[id],
					Result: res,
					OK:     okv,
				})
			case "error":
				if m, ok := ev["message"].(string); ok {
					streamErr = m
				}
			}
			return true
		}
		if err := streamClaudeCodeViaProxy(ccCtx, c, userID, role, body.Messages, systemPrompt, provider.upstreamModel, body.ClaudeSessionID, struct{ XpioRepo, ClusterID, DataApp string }{body.XpioRepo, body.ClusterID, body.DataApp}, emit); err != nil {
			fail(c, http.StatusBadGateway, 1502, "llm call: "+err.Error())
			return
		}
		finalText = sb.String()
		if streamErr != "" && finalText == "" {
			fail(c, http.StatusBadGateway, 1502, "llm call: "+streamErr)
			return
		}
		if finalText == "" && len(toolCalls) > 0 {
			finalText = "Done."
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"reply":             finalText,
				"tool_calls":        toolCalls,
				"model_used":        provider.id,
				"auto_routed":       autoRouted,
				"claude_session_id": ccSessionID,
				"usage": gin.H{
					"input_tokens":  0,
					"output_tokens": 0,
					"budget_used":   tokensUsedLast24h(userID),
					"budget_limit":  dailyTokenBudget(),
				},
			},
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 600*time.Second)
	defer cancel()

	// Tool-use loop.
	for i := 0; i < maxToolLoopIterations; i++ {
		maxTok := maxTokensPerTurn
		if provider.maxOutputTokens > 0 {
			maxTok = provider.maxOutputTokens
		}
		if body.Think && provider.addAnthropicVersion {
			maxTok = thinkingMaxTokens
		}
		req := map[string]any{
			"model":      provider.upstreamModel,
			"max_tokens": maxTok,
			"system":     systemPrompt,
			"messages":   anthMsgs,
			"tools":      tools,
		}
		// Forced tool for this turn. Only honoured when the caller already has
		// that tool — this narrows the model's choice, it never widens access.
		if tc := strings.TrimSpace(body.ToolChoice); tc != "" && toolAvailable(tools, tc) {
			req["tool_choice"] = map[string]any{"type": "tool", "name": tc}
		}
		if body.Think && provider.addAnthropicVersion {
			req["thinking"] = map[string]any{
				"type":          "enabled",
				"budget_tokens": thinkingBudgetTokens,
			}
		}
		resp, err := callLLM(ctx, provider, apiKey, req)
		if err != nil {
			fail(c, http.StatusBadGateway, 1502, "llm call: "+err.Error())
			return
		}
		if usage, ok := resp["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				totalInputTokens += int(v)
			}
			if v, ok := usage["output_tokens"].(float64); ok {
				totalOutputTokens += int(v)
			}
		}

		content, _ := resp["content"].([]any)
		stopReason, _ := resp["stop_reason"].(string)

		// If the agent produced any text, capture it. Tool use can be
		// interleaved with text in Claude's responses.
		toolUseBlocks := []map[string]any{}
		for _, block := range content {
			b, _ := block.(map[string]any)
			switch b["type"] {
			case "text":
				if t, ok := b["text"].(string); ok && t != "" {
					if finalText != "" {
						finalText += "\n\n"
					}
					finalText += t
				}
			case "tool_use":
				toolUseBlocks = append(toolUseBlocks, b)
			}
		}

		if stopReason != "tool_use" || len(toolUseBlocks) == 0 {
			break // agent is done; finalText holds the reply
		}

		// Add the assistant turn (with tool_use blocks) to history.
		anthMsgs = append(anthMsgs, map[string]any{
			"role":    "assistant",
			"content": content,
		})

		// Execute each tool call and append tool_result blocks.
		toolResultBlocks := []map[string]any{}
		for _, tu := range toolUseBlocks {
			toolName, _ := tu["name"].(string)
			toolID, _ := tu["id"].(string)
			args, _ := tu["input"].(map[string]any)

			result, callOK := dispatchTool(c, userID, role, toolName, args)
			toolCalls = append(toolCalls, toolCallResult{
				Name:   toolName,
				Args:   args,
				Result: result,
				OK:     callOK,
			})
			payload, _ := json.Marshal(result)
			content := string(payload)
			// On failure, hand the model an UNMISTAKABLE error envelope rather
			// than the raw result map. Weak models (e.g. kvrun-gemma4) otherwise
			// paper over a failed tool call with a plausible-sounding answer —
			// the dogfood "list_loops/app_detail ok=false → fabricated reply"
			// gap. We pull a human message out of `error`/`detail` (the LumidOS
			// bridge returns FastAPI's {"detail":...} on bad args / not-found),
			// flag it, and instruct the model to report the failure verbatim.
			if !callOK {
				msg := "the tool call failed"
				if e, ok := result["error"].(string); ok && e != "" {
					msg = e
				} else if d, ok := result["detail"].(string); ok && d != "" {
					msg = d
				}
				eb, _ := json.Marshal(map[string]any{
					"tool_failed": true,
					"error":       msg,
					"instruction": "This tool call FAILED. Tell the user it failed and why (use the error text); do NOT fabricate, guess, or substitute a plausible-sounding result.",
				})
				content = string(eb)
			}
			toolResultBlocks = append(toolResultBlocks, map[string]any{
				"type":        "tool_result",
				"tool_use_id": toolID,
				"content":     content,
				"is_error":    !callOK,
			})
		}
		anthMsgs = append(anthMsgs, map[string]any{
			"role":    "user",
			"content": toolResultBlocks,
		})
		// Loop continues — Claude sees the tool results, may call more
		// tools or produce a text reply.
	}

	if finalText == "" && len(toolCalls) > 0 {
		finalText = "Done."
	}

	// Record usage for the daily-budget cap. Best-effort — a DB write
	// failure shouldn't fail the chat response.
	if totalInputTokens+totalOutputTokens > 0 {
		_ = recordUsage(userID, "chat", "/me/agent/chat", provider.upstreamModel,
			totalInputTokens, totalOutputTokens)
	}

	// An app-grounded turn IS a cycle of the app's @trigger loop — that is what
	// "@trigger: it runs when you talk" means, and the app's Workflows page
	// promises the turn lands in the daily feed. It never did: chat called the
	// tools directly and produced no run, so the trajectory stayed empty and
	// last_run_ts stayed null. Same best-effort discipline as recordUsage above:
	// telemetry must never cost the user their answer.
	if body.Context != nil && len(toolCalls) > 0 {
		if app, ok := body.Context["app"].(string); ok && app != "" {
			if loop := triggerLoopFor(userID, app); loop != "" {
				recordChatCycle(userID, app, loop, provider.id, toolCalls, turnStartedAt)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"reply":       finalText,
			"tool_calls":  toolCalls,
			"model_used":  provider.id,
			"auto_routed": autoRouted,
			"usage": gin.H{
				"input_tokens":  totalInputTokens,
				"output_tokens": totalOutputTokens,
				"budget_used":   tokensUsedLast24h(userID),
				"budget_limit":  dailyTokenBudget(),
			},
		},
	})
}

// effectiveDailyBudget returns the per-user 24h token cap for a given
// provider: the provider's own override when set (>0), no cap when <0,
// else the global default. Lets the free in-cluster GPU models carry a
// generous backstop while paid Anthropic stays on the tight default.
func effectiveDailyBudget(p llmProvider) int {
	if p.dailyBudgetTokens != 0 {
		return p.dailyBudgetTokens
	}
	return dailyTokenBudget()
}

// dailyTokenBudget returns the per-user 24h cap on chat tokens, in
// total tokens (input + output). 0 means "no cap".
func dailyTokenBudget() int {
	v := strings.TrimSpace(os.Getenv("ANTHROPIC_DAILY_TOKEN_BUDGET"))
	if v == "" {
		return 50_000
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n
	}
	return 50_000
}

// tokensUsedLast24h sums input + output across all usage_events rows
// for this user with ts > now - 24h. Returns 0 on DB error so a
// transient failure doesn't lock the user out.
func tokensUsedLast24h(userSub string) int {
	cutoff := time.Now().Add(-24 * time.Hour)
	var totals struct {
		Inp int
		Out int
	}
	row := common.DB.
		Model(&models.UsageEvent{}).
		Where("user_sub = ? AND ts > ?", userSub, cutoff).
		// NB: `out` is a MySQL reserved word — aliasing to it yields a 1064
		// syntax error ("... as out FROM ...") and the budget query silently
		// fail-opens (usage always 0 ⇒ no enforcement). Use `outp`. Scan is
		// positional, so the alias name doesn't affect the read below.
		Select("COALESCE(SUM(input_tokens), 0) as inp, COALESCE(SUM(output_tokens), 0) as outp").
		Row()
	if row != nil {
		// On a scan error this returns 0 — i.e. budget enforcement fails OPEN
		// (a DB blip mustn't lock every non-admin out of chat). Log it so the
		// outage is greppable rather than silently un-metered.
		if err := row.Scan(&totals.Inp, &totals.Out); err != nil {
			log.Printf("[me-agent] budget query failed user=%s err=%v (treating usage as 0, fail-open)", userSub, err)
		}
	}
	return totals.Inp + totals.Out
}

// recordUsage appends one usage_events row. Safe to call concurrently.
func recordUsage(userSub, kind, endpoint, model string, inTok, outTok int) error {
	ev := models.UsageEvent{
		UserSub:      userSub,
		Kind:         kind,
		Endpoint:     endpoint,
		Model:        model,
		InputTokens:  inTok,
		OutputTokens: outTok,
		// Cost in cents — Haiku 4.5 is roughly $0.25/M input, $1.25/M
		// output (May 2026). Round up to integer cents; finer
		// accounting can come later if it matters.
		CostCents: (inTok*25 + outTok*125) / 1_000_000,
	}
	return common.DB.Create(&ev).Error
}

// anthropicKey resolves the API key from env first, then from
// /home/webmaster/.api_keys/anthropic on disk (mode 0600 file with the
// raw key as the first line).
func anthropicKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
		return k, nil
	}
	if b, err := os.ReadFile("/home/webmaster/.api_keys/anthropic"); err == nil {
		key := strings.TrimSpace(strings.Split(string(b), "\n")[0])
		if key != "" {
			return key, nil
		}
	}
	return "", fmt.Errorf("no ANTHROPIC_API_KEY set")
}

// lumidLLMBase resolves the base URL of the in-cluster lumid-llm gateway
// (the model-routed proxy that speaks Anthropic /v1/messages). Reads
// LUMID_LLM_BASE (e.g. http://lumid-llm:8088), defaulting to that in-cluster
// Service; any trailing slash or accidental /v1[/messages] suffix is trimmed
// so callers can safely append "/v1/messages".
func lumidLLMBase() string {
	base := strings.TrimSpace(os.Getenv("LUMID_LLM_BASE"))
	if base == "" {
		base = "http://lumid-llm:8088"
	}
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/v1/messages")
	base = strings.TrimSuffix(base, "/v1")
	return strings.TrimRight(base, "/")
}

// kvrunPAT resolves the Lumid PAT used to authenticate against the lumid-llm
// gateway. Env first (KVRUN_LLM_TOKEN), then /home/webmaster/.lumilake/pat.
func kvrunPAT() (string, error) {
	if k := strings.TrimSpace(os.Getenv("KVRUN_LLM_TOKEN")); k != "" {
		return k, nil
	}
	if b, err := os.ReadFile("/home/webmaster/.lumilake/pat"); err == nil {
		tok := strings.TrimSpace(strings.Split(string(b), "\n")[0])
		if tok != "" {
			return tok, nil
		}
	}
	return "", fmt.Errorf("no KVRUN_LLM_TOKEN set")
}

// callLLM POSTs to the provider's /v1/messages endpoint with
// Anthropic-shaped JSON. Provider determines auth header + key source.
// Returns the parsed JSON body on 2xx, or an error otherwise
// (including the response body for debug).
func callLLM(ctx context.Context, p llmProvider, apiKey string, body map[string]any) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(p.authHeader, p.authPrefix+apiKey)
	if p.addAnthropicVersion {
		req.Header.Set("anthropic-version", anthropicVersion)
	}

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	respBody, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %d: %s", p.id, r.StatusCode, string(respBody[:min(400, len(respBody))]))
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildSystemPrompt — the agent's persona + a snapshot of the user's
// current app inventory so it has context without an extra tool call.
// resolvePromptAndTools — single decision point for the chat's
// system prompt + tool catalog. Three modes, in priority order:
//
//  1. PersonaID set → persona's system_prompt + allowed_tools filter
//     (mutually exclusive with agent_id).
//  2. AgentID set   → standard LumidOS prompt + agent-bank block
//     replacing me-prefs.
//  3. Default       → standard LumidOS prompt + me-prefs block.
//
// Returns (systemPrompt, tools, preferredModel). preferredModel is
// honored only when the request didn't set Model explicitly (handler-
// level concern, not done here).
//
// wantTools=false skips the tool-catalog build (and the persona tool
// filter) entirely — the claude-code path replaces our tools with the
// CLI's own, so constructing the full catalog there is dead work.
func resolvePromptAndTools(userID, role string, body meAgentChatBody, wantTools bool) (string, []map[string]any, string) {
	var tools []map[string]any
	if wantTools {
		tools = buildToolDefsForRole(role)
	}
	// Viewing context rides on every prompt variant (persona included) —
	// it's per-request situational awareness, not persona flavor. Both
	// the streaming and non-streaming endpoints, and the claude-code
	// CLI delegation (which receives systemPrompt as context), inherit
	// it from here.
	ctxBlock := renderViewingContext(body.Context)
	// When grounded on an app, tell the agent what it can DO there (operable
	// actions), so it offers concrete help instead of just describing.
	if body.Context != nil {
		if app, ok := body.Context["app"].(string); ok && app != "" {
			ctxBlock += groundedActionsHint(userID, app)
			// Works on EVERY provider, including claude-code, which never receives
			// identity's tool catalog — a file-capable agent can adopt the app's
			// voice from its prompts without needing a tool at all.
			ctxBlock += appVoiceHint(userID, app)
			// Voice alone left the tool-less path in character but without the
			// case; carry the content too, so picking a case works on every model.
			if n := len(body.Messages); n > 0 {
				// The question index is derived from the transcript, not sent by the
				// client: a candidate who could set it would simply ask for Q4.
				ctxBlock += appDataHint(userID, app, body.Messages[n-1].Content,
					chatMode(body.Context), answeredQuestions(body.Messages))
			}
		}
	}
	if body.PersonaID != "" {
		p, _ := loadPersona(userID, body.PersonaID)
		if p != nil {
			if wantTools && len(p.AllowedTools) > 0 {
				allow := map[string]bool{}
				for _, t := range p.AllowedTools {
					allow[t] = true
				}
				tools = filterTools(tools, allow)
			}
			return p.SystemPrompt + ctxBlock, tools, p.PreferredModel
		}
		// Fall through if persona id is invalid — chat still works.
	}
	return buildSystemPrompt(userID, role, body.AgentID) + ctxBlock, tools, ""
}

// renderViewingContext turns the Studio shell's structured "what the
// user is looking at" payload into a system-prompt block with tool
// grounding hints, so "this run" / "this app" resolve without the user
// re-stating them. Empty/absent context renders nothing.
func renderViewingContext(ctx map[string]any) string {
	if len(ctx) == 0 {
		return ""
	}
	str := func(k string) string {
		v, _ := ctx[k].(string)
		return v
	}
	var b strings.Builder
	b.WriteString("\n\n## Viewing context (this turn)\n")
	if p := str("path"); p != "" {
		fmt.Fprintf(&b, "The user is on %s", p)
		if pg := str("page"); pg != "" {
			fmt.Fprintf(&b, " (%s page)", pg)
		}
		b.WriteString(".\n")
	}
	app, loop, runID := str("app"), str("loop"), str("run_id")
	if app != "" {
		fmt.Fprintf(&b, "Grounding: \"this app\" = %s.", app)
		if loop != "" {
			fmt.Fprintf(&b, " \"This workflow\" = %s (pass app=%s, loop=%s to workflow/loop tools).", loop, app, loop)
		}
		b.WriteString("\n")
		// The app workspace shows the app's structured details (workflows, runs,
		// pipeline) in its own panel — so the chat must NOT re-dump them. Reveal
		// PROGRESSIVELY: answer with one focused thing + the single best next
		// step, and only surface a specific data card (show_app_surface / one
		// entity card) when explicitly asked. Never paste whole tables/lists.
		b.WriteString("Style: this is the app's grounded chat beside its details panel. Be progressive/hierarchical — one focused point + the next step per turn; don't dump tables, run lists, or the whole surface (the panel already shows them); pull in a single card only when asked.\n")
	}
	if cy, ok := ctx["cycle"].(map[string]any); ok {
		ca, _ := cy["app"].(string)
		cl, _ := cy["loop"].(string)
		cts, _ := cy["ts"].(string)
		if ca != "" && cl != "" && cts != "" {
			fmt.Fprintf(&b, "\"This run\" = the open run: app=%s loop=%s ts=%s (pass these to run/cycle tools).\n", ca, cl, cts)
		}
	} else if runID != "" {
		fmt.Fprintf(&b, "\"This run\" = run_id=%s.\n", runID)
	}
	renderRef := func(label string, m map[string]any) {
		kind, _ := m["kind"].(string)
		id, _ := m["id"].(string)
		if kind == "" || id == "" {
			return
		}
		fmt.Fprintf(&b, "%s: %s id=%s", label, kind, id)
		if lb, _ := m["label"].(string); lb != "" {
			fmt.Fprintf(&b, " (%q)", lb)
		}
		if affs, ok := m["affordances"].([]any); ok && len(affs) > 0 {
			parts := make([]string, 0, len(affs))
			for _, a := range affs {
				if s, ok := a.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				fmt.Fprintf(&b, " — available actions: %s", strings.Join(parts, ", "))
			}
		}
		b.WriteString("\n")
	}
	if sel, ok := ctx["selection"].(map[string]any); ok {
		renderRef("Page selection", sel)
	}
	if pk, ok := ctx["picked"].(map[string]any); ok {
		// The user-pinned pick is the explicit referent — it wins over
		// the page selection when both could answer "this".
		renderRef("User is POINTING AT (primary referent)", pk)
	}
	b.WriteString("Use this context silently — don't recite it back. When the user says \"this\"/\"it\"/\"here\", resolve against the grounding above before asking them to clarify.\n")
	return b.String()
}

// buildToolDefsForRole returns the tool list a caller may use. EVERY role
// now gets the full catalog — including write_file, edit_file, multi_edit,
// and bash_exec — because access is scoped structurally by the jail
// (writeRoot confines writes to the caller's own tenant workspace; bash runs
// non-super in a network-free Docker sandbox over that same workspace), not
// by hiding tools per role. "Highest capabilities for all users", with
// isolation preserved by the sandbox rather than by capability removal.
func buildToolDefsForRole(role string) []map[string]any {
	// Generic "operate any app" tools (app_actions/app_read/show_app_surface/
	// app_action/qa_call) are available to every role — gated by the
	// formActions + scheme/path allowlists + approval, not by role.
	defs := append(buildToolDefs(), appOpsToolDefs()...)
	// Account self-service (own tokens/profile) — available to every role.
	defs = append(defs, accountToolDefs()...)
	// Media generation (image + speech via the lumid-llm gateway) — every role.
	defs = append(defs, mediaToolDefs()...)
	// Admin control-plane tools are advertised only to admin/super_admin (the
	// model never sees them otherwise); dispatch re-checks role as well.
	if role == "admin" || role == "super_admin" {
		defs = append(defs, adminToolDefs()...)
		defs = append(defs, clusterToolDefs()...)
	}
	// Operator control-plane (ops-agent healthcheck/remediate) is super_admin-only
	// — the model never sees it for any lesser role; dispatch re-checks too.
	if role == "super_admin" {
		defs = append(defs, operatorToolDefs()...)
	}
	return defs
}

// buildSystemPrompt assembles the assistant's persona + a snapshot
// of the user's current tenant. When agentID is set, the trailing
// memory block swaps from the user's me-prefs to that agent's bank
// (see renderAgentBankBlock); empty agentID falls through to the
// default me-prefs path.
func buildSystemPrompt(userID, role, agentID string) string {
	apps := []string{}
	// Caller's tenant first.
	if entries, err := os.ReadDir(tenantAppsDir(userID)); err == nil {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				apps = append(apps, e.Name())
			}
		}
	}
	tenantList := "(none)"
	if len(apps) > 0 {
		tenantList = strings.Join(apps, ", ")
	}

	return `You are the LumidOS assistant — a focused helper that automates what the user wants via their installed apps.

You have tools to:
  - list, install, uninstall apps from xp.io
  - start, stop, or fire one-off runs of an app's workflows
  - record the user's feedback on runs (what worked, what to change)
  - query recent run results
  - search the web (web_search), fetch one URL (web_fetch), or run deep research (deep_research)
  - look up financial data by symbol (query_findata)
  - remember things about the user long-term (remember_about_me) — call this whenever the user shares a preference, fact about themselves, or a working style hint that should persist
  - generate an image from a prompt (generate_image) or synthesize speech from text (text_to_speech) — call these when the user asks you to draw/render a picture or read something aloud; the result appears inline in their artifact panel

When the user expresses an intent, prefer doing the work via tools over describing how they could do it themselves. Confirm what you did in 1-2 sentences after each action. When the user asks you to run, pause, install, fork, or publish something, you MUST call the matching tool in that same turn — never answer with prose alone, and never claim an action happened without its tool result.

ATTACHMENTS & GENERAL HELP: when the user attaches a file (PDF, document, spreadsheet, image, text) or pastes content, work with it DIRECTLY — summarize, analyze, extract, translate, or answer questions about it. That is core assistant work, fully in scope. Likewise for ordinary questions, drafting, explanation, and analysis: just help. NEVER preface a reply with a disclaimer that document summarization or general questions are "outside what you do" or that you're "scoped to apps/workflows" — you are a genuinely helpful assistant first, and the app/workflow/codebase tools below are ADDITIONAL powers, not a restriction on what you will answer.

RUNNING A WORKFLOW: when the user explicitly asks to run, trigger, fire, or kick off a workflow (e.g. "run mbb-ai's case_cycle", "run the morning brief now", "run it in paper mode"), CALL run_loop_now with that app and workflow in the same turn — do NOT just describe where to watch it, and do NOT route them to the Workflows tab instead of running. If you don't know the exact workflow name, call list_apps (or the app's detail) to resolve it, then run it. Firing a run of an already-installed workflow is safe and needs no approval. After the tool returns a queued run, confirm in one line what you ran and link the workflow so they can watch it (see Linking into the Studio below).

VOCABULARY: in replies, always say "app", "workflow", and "run" — never internal terms like "loop", "cycle", "intent", or raw tool names. When the user asks how to watch progress or inspect PAST results, point them at the app page's Workflows tab (each run there is inspectable stage by stage) — do NOT recite tool names like loop_status or loop_history. (This is for inspection; when they ask to RUN something, run it per the rule above rather than pointing them at the tab.)

The user already has these apps installed in their tenant: ` + tenantList + `

When you don't know an app's slug, call list_marketplace first. When the user gives ambiguous feedback ("today was off"), capture it as a feedback note on the most recent run of the most likely workflow and tell them you did so — they can refine later.

## Creating a new workflow — roll it out as a conversation, one clear step at a time
When the user wants to build a new workflow/app (e.g. they say "create a workflow" or "new intent"), GUIDE them — never dump a pre-baked template, and do NOT assume crypto trading. Walk these steps, each as its own short turn:
  1. ASK what it should do, in plain words: what should it watch (observe), what decision or output it should make, and how often it should run. One or two brief questions — don't interrogate.
  2. COMPOSE: once you have enough, call compose_workflow with their intent (and a name if they gave one).
  3. PRESENT THE PIPELINE CLEARLY: from the compose result, lay out the assembled steps as a NUMBERED list, one per line, in the form "N. <Stage> — <skill>: <what this step does>". Then state the schedule and the goal in one line each. Every step must be legible so they know exactly what will run.
  4. CONFIRM + INSTALL: ask "Want me to install it?" — on yes, call install_app with the draft slug, then offer to run the first cycle.
Keep each turn tight and concrete. Adapt the domain to whatever they describe — research, monitoring, annotation, trading, anything.

## Linking into the Studio
When your answer references an app, workflow, or run, link it with a plain markdown link — these navigate in-app:
  - app page:        /studio/apps/<app>
  - workflow open:   /studio/apps/<app>?selected=<loop>
  - one run open:    /studio/apps/<app>?selected=<loop>&cycle=<ts>
  - activity feed:   /studio/runs    · inbox: /studio/inbox    · knowledge: /studio/knowledge
Example: "the [morning brief](/studio/apps/personal-agent?selected=morning_brief) failed twice". Prefer a link over telling the user where to click.

Stay grounded: don't invent apps, loops, or features. If a tool fails, surface the error briefly and suggest the next step.` + func() string {
		extra := ""
		if role == "super_admin" || role == "admin" {
			access := "You can READ any file under /proj/ with read_file. "
			if role == "super_admin" {
				access += "You may also write/edit files and run shell commands against /proj/."
			} else {
				access += "Access to /proj/ is READ-ONLY — write_file, edit_file, and bash_exec do NOT reach /proj/ for your role (they're confined to your own tenant workspace), so don't attempt to modify the deployment codebase. You CAN freely write within your own workspace."
			}
			extra = `

## Codebase access
` + access + `
Key services and their locations:
  lumid_identity  → lumid_identity/          (Go auth service, port 9900)
  QuantArena      → quantarena/backend/      (Go API, ports 9988/9999)
  LumidOS SDK     → LumidOS/LumidOS/         (Python orchestration)
  lumid_ui        → lumid_ui/src/            (React frontend)
  flowmesh        → flowmesh/                (GPU task dispatcher)
  runmesh         → runmesh/backend/         (Java cloud service)
  LQT             → LQT/                     (Rust knowledge app)

To explore a service: call read_file with path like 'lumid_identity/' (returns directory listing), then drill into specific files. Example: read_file('lumid_identity/configs/identity.yaml') or read_file('lumid_identity/internal/handler/router.go').

INSTALLED APPS live outside the codebase — read them by app name and read_file resolves the bundle automatically: read_file('<app>/xpcloud.yaml'), read_file('<app>/ui/home.md'), read_file('<app>/commands/'). Use this when asked to debug an installed app (e.g. a failing widget or loop).

Search the tree with glob_files('**/*.go') / grep_files('pattern', path_glob='**/*.go') instead of guessing paths. For multi-spot edits to one file, prefer multi_edit. Fan out independent investigations with spawn_agents.`
		} else {
			extra = `

## Your workspace
You have a private, isolated workspace. Find files with glob_files('**/*') and grep_files('pattern'); read them with read_file; create/modify them with write_file, edit_file, or multi_edit (these ask for your approval first). bash_exec runs commands in a network-free sandbox with your workspace mounted. Delegate parallel sub-tasks with spawn_agents. Everything is confined to your own space — you can't see or touch anyone else's.`
		}
		extra += renderTasksBlock(userID)
		if agentID != "" {
			return extra + renderAgentBankBlock(userID, agentID)
		}
		return extra + renderPrefsBlock(userID)
	}()
}

// buildToolDefs — the Anthropic-format tool schema.
func buildToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_apps",
			"description": "List the user's installed xpio apps (their tenant + operator-shared).",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "install_app",
			"description": "Install an xpio app from xp.io into the user's tenant. Use list_marketplace first if you don't know the slug.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string", "description": "owner_sub/name or first-party shorthand (e.g. 'personal-agent')"},
					"as":   map[string]any{"type": "string", "description": "optional rename"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "uninstall_app",
			"description": "Remove an installed app from the user's tenant.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "run_loop_now",
			"description": "Fire a one-shot cycle of a loop without waiting for the schedule. Optional `cases` scopes the run to a subset (e.g. one case_id or a comma-separated list) for apps whose loop templates {{ args.cases }} (e.g. mbb-ai's regression_sweep) — omit to run the full set.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string"},
					"loop":  map[string]any{"type": "string"},
					"cases": map[string]any{"type": "string", "description": "Optional run scope — a case_id (e.g. 'Case_019') or comma-separated ids. Omit for all cases."},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "stop_loop",
			"description": "Cooperatively stop a RUNNING workflow cycle (the inverse of run_loop_now). The runner aborts at its next LLM call and the run is marked interrupted. Use when the user says 'stop', 'cancel', 'halt' a running workflow. Safe + reversible — just re-run to restart.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string"},
					"loop": map[string]any{"type": "string"},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "cycle_detail",
			"description": "Inspect ONE run of a workflow: per-step status, outputs, errors, prompt audit (sha + preview), sidecar artifacts, and memories learned. The go-to tool for 'why did this run fail?' / 'what happened in this run?'. ts accepts 'latest'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string"},
					"loop": map[string]any{"type": "string"},
					"ts":   map[string]any{"type": "string", "description": "Run timestamp dir (e.g. 20260611T193609Z) or 'latest'."},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "loops_health",
			"description": "Health snapshot of EVERY workflow: status (ok|failing|stale|never|manual), consecutive failures, last error for failing ones. Use for 'how are my workflows doing?' / 'what's broken?'. Failures sort first.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "review_action",
			"description": "Act on a run's review queue: approve a held action, revamp a step with new instructions, or dismiss. Mirrors the inspector's review buttons.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":               map[string]any{"type": "string"},
					"loop":              map[string]any{"type": "string"},
					"decision":          map[string]any{"type": "string", "enum": []string{"approve", "revamp", "dismiss"}},
					"step_id":           map[string]any{"type": "string"},
					"step_instructions": map[string]any{"type": "string", "description": "Required for revamp — the new instructions for that step."},
					"outbox_ref":        map[string]any{"type": "string"},
				},
				"required": []string{"app", "loop", "decision"},
			},
		},
		{
			"name":        "experiment_case",
			"description": "Drill into one case of an app experiment: all result rows + the latest metrics per question.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":     map[string]any{"type": "string"},
					"id":      map[string]any{"type": "string", "description": "experiment id"},
					"case_id": map[string]any{"type": "string"},
				},
				"required": []string{"app", "id", "case_id"},
			},
		},
		{
			"name":        "loop_metric_series",
			"description": "A workflow's KPI trajectory over its recent runs (per-metric time series). Use for 'is it improving?' / 'plot the trend'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string"},
					"loop": map[string]any{"type": "string"},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "casebook",
			"description": "The data casebook a workflow's goal metrics are scored on: each case with its latest score + score history, plus how the casebook's metrics evolved. Metrics are scoped to the loop's experiment. Use for 'what cases / which regressed / how is the data scored'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string"},
					"loop": map[string]any{"type": "string", "description": "loop name (scopes metrics to that workflow's experiment)"},
				},
				"required": []string{"app"},
			},
		},
		{
			// Without this, an app's declared tools[] are unreachable from chat:
			// app_run returns a PROCEDURE rather than executing one, and nothing
			// else dispatches an app's own commands. So a free-form question got
			// answered by deep_research and the app never participated — its
			// analyst voice, its skill cards and its grounded/ungrounded scoring
			// all sat unused. This is the missing verb.
			"name": "app_answer",
			// Imperative on purpose. With a permissive description a small model
			// answers domain questions from its own knowledge and the app never
			// participates — which is the exact failure this tool exists to fix,
			// so a tool that is merely *available* is not enough.
			"description": "REQUIRED for any domain/subject-matter question asked while an app is in context — including free-form ones with no case id. Answers AS that app's analyst using the app's own prompts and skill cards, and reports whether the answer is backed by ground truth. Do NOT answer such a question yourself and do NOT use web_search or deep_research for it: the app's voice, rubric and grounded/ungrounded distinction only exist here. Pass the user's question verbatim.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string"},
					"question": map[string]any{"type": "string", "description": "the user's question, verbatim"},
					"case_id":  map[string]any{"type": "string", "description": "optional labelled case; omit for an open question"},
				},
				"required": []string{"app", "question"},
			},
		},
		{
			// The scoring verb. "Score my last answer" used to be served by
			// app_answer, which reports grounded:true because a case was LOADED —
			// nothing checked a keypoint, yet the reply claimed the answer was
			// evaluated against ground truth. This is the tool that actually
			// compares, and the only one that may hold the answer key.
			"name":        "app_judge",
			"description": "REQUIRED whenever the user asks for a score, an evaluation, or how well an answer did while an app is in context. Compares the answer against the case's real ground-truth keypoints and returns covered/total plus per-axis scores. Do NOT use app_answer for scoring and do NOT estimate a score yourself — only this tool sees the rubric, so any other number is invented.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string"},
					"answer":   map[string]any{"type": "string", "description": "the answer being scored, verbatim"},
					"question": map[string]any{"type": "string", "description": "the question it answered"},
					"case_id":  map[string]any{"type": "string", "description": "the labelled case; omit for an open answer (score will be reported as ungrounded)"},
				},
				"required": []string{"app", "answer"},
			},
		},
		{
			// give_feedback needs app+loop+ts because it scores a scheduled CYCLE;
			// an interactive answer has no run to point at, so a user correcting
			// something in chat had nowhere to send it. This is that route.
			"name":        "app_feedback",
			"description": "Record a correction against an installed app and stage it for human review. Use when the user says an answer was wrong or should have been different. Do NOT use give_feedback for this — that scores a scheduled cycle run and needs a loop + timestamp.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":    map[string]any{"type": "string"},
					"note":   map[string]any{"type": "string", "description": "what was wrong, in the user's words"},
					"rating": map[string]any{"type": "number", "description": "-1 negative, 1 positive; optional"},
				},
				"required": []string{"app", "note"},
			},
		},
		{
			"name":        "app_config_get",
			"description": "Read an installed app's xpcloud.yaml (workflows, schedules, skill imports, publish policy). Returns the YAML + a sha for optimistic-locked writes.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "app_config_set",
			"description": "Overwrite an installed app's xpcloud.yaml. Validates YAML; pass base_sha from app_config_get to avoid clobbering concurrent edits. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string"},
					"yaml":     map[string]any{"type": "string"},
					"base_sha": map[string]any{"type": "string"},
				},
				"required": []string{"app", "yaml"},
			},
		},
		{
			"name":        "knowledge_agents",
			"description": "List the USER's own knowledge agents (their tenant banks) with memory counts. Prefer this over xp_agents, which reads the operator host.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "knowledge_memories",
			"description": "Newest memories from one of the USER's knowledge agents. Prefer this over xp_memories, which reads the operator host.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent": map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer", "description": "max rows (default 25, cap 100)"},
				},
				"required": []string{"agent"},
			},
		},
		{
			"name":        "give_feedback",
			"description": "Record the user's feedback on a cycle. Use after the user says something evaluative about a result. Rating: -1 bad, 0 neutral, +1 good.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":    map[string]any{"type": "string"},
					"loop":   map[string]any{"type": "string"},
					"ts":     map[string]any{"type": "string", "description": "Cycle timestamp dir name, e.g. 20260522T150000Z. Use 'latest' to target the most recent cycle of that loop."},
					"rating": map[string]any{"type": "integer", "enum": []int{-1, 0, 1}},
					"note":   map[string]any{"type": "string", "description": "The user's natural-language feedback. Quote them when possible."},
				},
				"required": []string{"app", "loop", "ts", "note"},
			},
		},
		{
			"name":        "intent_audit",
			"description": "Show what's changed about an intent over a time window — across the six improvement axes (examples=cases learned from, standard=metrics & rubric, recipe=workflow steps, pieces=skills, memory=banks, rules=patterns figured out). Use when the user asks 'what changed this week?', 'why did the metric move?', 'show me the audit', or when explaining how the AI is adapting. Returns events newest-first + a per-axis movement summary.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string", "description": "intent id (xpio app name, e.g. personal-agent)"},
					"loop":  map[string]any{"type": "string", "description": "optional: scope to one loop"},
					"since": map[string]any{"type": "string", "description": "either 'Nd' (last N days) or an RFC3339 timestamp. Default: last 7d."},
					"limit": map[string]any{"type": "integer", "default": 30, "description": "max events to return"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "list_recent_cycles",
			"description": "List the most recent cycle timestamps for a loop. Useful before give_feedback to find the right ts.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string"},
					"loop":  map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer", "default": 5},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "list_marketplace",
			"description": "Browse the xp.io marketplace for apps to install. Returns slug + summary.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":     map[string]any{"type": "string", "description": "search keyword"},
					"limit": map[string]any{"type": "integer", "default": 10},
				},
			},
		},
		{
			"name":        "query_my_knowledge",
			"description": "Search the user's accumulated knowledge banks. Returns matching memory snippets with their agent/source. Use when the user asks 'what did I learn about X' or when you need prior context before suggesting an action.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "search terms — keyword match for now"},
					"agent": map[string]any{"type": "string", "description": "optional: scope to a specific agent (e.g. 'admin-personal-assistant')"},
					"limit": map[string]any{"type": "integer", "default": 6},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "subscribe_to_bank",
			"description": "Subscribe to another tenant's public knowledge bank on xp.io. Memories from the source flow into the target agent on its next cycle, giving the user the benefit of other users' patterns without manual curation. Hook 3 (silent compounding intelligence).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"source_slug":     map[string]any{"type": "string", "description": "xp.io repo slug of the bank to subscribe to (owner_sub/bank-name)"},
					"target_agent_id": map[string]any{"type": "string", "description": "local agent id that should receive the imported memories. If absent, defaults to the agent whose name matches the source bank's name."},
				},
				"required": []string{"source_slug"},
			},
		},
		// Phase S6c — close the gap between "show me" and "do it for me".
		// Drafts, loop tuning, and the today summary are the natural-
		// language commands users reach for: "send Alice's draft",
		// "pause cc_watcher for the weekend", "what's pending?".
		{
			"name":         "today_summary",
			"description":  "Return the user's headlines + recent cycles + drafts-pending count in one shot. Use when the user asks 'what's pending', 'what's new', or 'what did my AI do today?'.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "list_drafts",
			"description": "List the user's pending email/calendar drafts the AI has proposed but not yet sent. Each draft has id, subject, to, body, app. Use when the user asks about pending replies or wants you to act on a specific one.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string", "description": "optional — limit to one app's drafts"},
				},
			},
		},
		{
			"name":        "send_draft",
			"description": "Send a drafted email/event by id. The send goes through the user's OAuth grant — irreversible. Confirm with the user before calling unless they explicitly said 'send'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string", "description": "draft id from list_drafts"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "edit_draft",
			"description": "Rewrite a draft's body or subject. State resets to pending (the user still has to send it). Use when the user wants a tone shift, more detail, or a quick fix.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":      map[string]any{"type": "string"},
					"body":    map[string]any{"type": "string", "description": "new body text"},
					"subject": map[string]any{"type": "string", "description": "optional new subject"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "dismiss_draft",
			"description": "Mark a draft dismissed — no send, no further nudges. Use when the user says 'skip', 'ignore', 'not this one'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "patch_loop",
			"description": "Change a loop's schedule or pause/resume it. Writes to .user-overrides.yaml; the underlying app stays untouched. Use for 'pause cc_watcher', 'change morning_brief to 7am', 'resume hourly_triage'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string"},
					"loop":     map[string]any{"type": "string"},
					"schedule": map[string]any{"type": "string", "description": "cron expression, e.g. '0 8 * * *'"},
					"enabled":  map[string]any{"type": "boolean", "description": "true to resume, false to pause"},
				},
				"required": []string{"app", "loop"},
			},
		},

		// ── Workflow surface (W1) ─────────────────────────────────
		// In the user-facing vocabulary, "workflow" replaces "loop" /
		// "app" / "n8n DAG" — all three are kinds of workflow. The
		// old list_apps / run_loop_now / patch_loop tools stay above
		// for back-compat; the new tools below are the canonical
		// surface the chat should prefer.
		{
			"name":        "list_workflows",
			"description": "List the user's workflows across kinds (scheduled = xpio loop; visual = n8n DAG). Returns slug, kind, trigger, last-run state, enabled flag. Prefer this over list_apps.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind": map[string]any{
						"type":        "string",
						"description": "optional filter: 'scheduled' or 'visual'",
						"enum":        []string{"scheduled", "visual"},
					},
				},
			},
		},
		{
			"name":        "workflow_detail",
			"description": "Full definition + last runs for one workflow. Slug shape: '<app>:<loop>' for scheduled or 'n8n:<id>' for visual.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "list_runs",
			"description": "List recent workflow runs across all kinds. Filter by state ('succeeded'/'failed'/'running'/'skipped') and/or workflow slug. Default window: last 24h.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"state":    map[string]any{"type": "string", "description": "comma-separated states to include"},
					"workflow": map[string]any{"type": "string", "description": "filter to one workflow slug"},
					"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
				},
			},
		},
		{
			"name":        "run_detail",
			"description": "Per-step details for one run (steps, error, artifacts). run_id shape: 'scheduled:<app>:<loop>:<ts>' or 'visual:n8n:<exec_id>'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string"},
				},
				"required": []string{"run_id"},
			},
		},
		{
			"name":        "pause_workflow",
			"description": "Pause (enabled=false) or resume (enabled=true) a workflow. Equivalent to patch_loop with the enabled flag, but accepts the workflow's slug directly.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":    map[string]any{"type": "string", "description": "<app>:<loop> for scheduled workflows"},
					"enabled": map[string]any{"type": "boolean"},
				},
				"required": []string{"slug", "enabled"},
			},
		},

		// ── Create surface (W2) — chat-driven workflow composition.
		// These are the highest-value Create tools; they hide the
		// marketplace-mechanics from the user (they ask "build me X",
		// the agent picks skills + drafts a workflow).
		{
			"name":        "search_marketplace",
			"description": "Search the curated marketplace for skills / workflows matching a natural-language query. Use this when the user is browsing or you need to know what's available before composing.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":   map[string]any{"type": "string"},
					"for_app": map[string]any{"type": "string", "description": "optional — narrow to one xpio app's catalog (personal-agent / mbb-ai / auto-quant / eventx / auto-sysresearch)"},
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "compose_workflow",
			"description": "Draft a new workflow from a natural-language intent. Calls /api/v1/skills/suggest to pick the right skills, builds an xpcloud.yaml workflow stitching them together, and stages it under the user's tenant draft directory. The user can then review + adjust in the composer UI.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"intent":  map[string]any{"type": "string", "description": "plain-English description, e.g. 'watch my Slack every hour and draft replies'"},
					"for_app": map[string]any{"type": "string", "description": "which xpio shape to target — personal-agent is the default for assistant-style intents"},
					"name":    map[string]any{"type": "string", "description": "optional — friendly name for the new workflow (defaults to a slug derived from the intent)"},
				},
				"required": []string{"intent"},
			},
		},
		{
			"name":        "add_skill_to_workflow",
			"description": "Add a skill from the marketplace to an existing scheduled workflow's skill_imports[]. Updates the tenant's .user-overrides.yaml. Use after compose_workflow when the user wants to extend an already-installed workflow.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":       map[string]any{"type": "string", "description": "workflow slug, e.g. 'personal-agent:morning_brief'"},
					"skill_name": map[string]any{"type": "string", "description": "marketplace skill name, e.g. 'tavily-search'"},
				},
				"required": []string{"slug", "skill_name"},
			},
		},

		// ── Improve surface (W4) ──────────────────────────────────
		{
			"name":        "workflow_report_card",
			"description": "Plain-English progress card for one workflow over the last month vs the month before. Headlines cover reliability, latency, draft accept-rate. Use this for 'how is my morning brief getting better?' or 'is X workflow improving?' questions.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string", "description": "workflow slug, e.g. 'personal-agent:morning_brief'"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "trigger_evaluation",
			"description": "Enqueue an on-demand evaluation of a marketplace skill against an xpio app's casebook. Skill-roster picks it up within ~60s and posts an attestation to xpcloud. Use when the user wants a fresh score (e.g., right after installing a new skill).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"skill_name": map[string]any{"type": "string"},
					"for_app":    map[string]any{"type": "string", "description": "personal-agent / mbb-ai / eventx / auto-quant / auto-sysresearch"},
				},
				"required": []string{"skill_name", "for_app"},
			},
		},
		{
			"name":        "suggest_workflow_improvement",
			"description": "Look at one workflow's recent failures + report card and recommend ONE concrete change (swap skill, add a step, change schedule). Use when the user asks 'how can I improve X?' or after surfacing a failure they want to fix.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "web_search",
			"description": "Search the open web for a short query. Returns 5-10 result snippets with URLs. Use for current events, factual lookups, or to find authoritative sources to follow up with web_fetch. For multi-source synthesis with a written-up answer, prefer deep_research instead.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":       map[string]any{"type": "string", "description": "Search terms — natural language is fine."},
					"num_results": map[string]any{"type": "integer", "description": "Optional, default 5, max 10."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "web_fetch",
			"description": "Fetch one URL and return its readable content as markdown. Use after web_search when the user wants the actual content of a specific page, not just snippets.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "Absolute URL (https://…)."},
				},
				"required": []string{"url"},
			},
		},
		{
			"name":        "deep_research",
			"description": "Multi-source web research with a synthesized answer. Returns a written brief plus the supporting result list. Use when the user asks a question that needs research across multiple sources (e.g. 'what's the current state of X?', 'compare A and B', 'summarize recent developments on Z'). Slower (10-30s) than web_search; choose web_search for simple lookups.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"question":    map[string]any{"type": "string", "description": "The research question, in natural language."},
					"max_results": map[string]any{"type": "integer", "description": "Optional, default 8, max 10. Lower is faster."},
				},
				"required": []string{"question"},
			},
		},
		{
			"name":        "query_findata",
			"description": "Look up financial data for a stock/ETF symbol via the kv.run:5000 warehouse. Faster + cheaper than web_search for price + corporate-action queries. Kinds: quote (current price + volume), news (recent headlines), earnings (calendar + results), peers (similar tickers), filings (SEC filings), ohlc (30-day daily bars).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind":   map[string]any{"type": "string", "enum": []string{"quote", "news", "earnings", "peers", "filings", "ohlc"}, "description": "What to fetch."},
					"symbol": map[string]any{"type": "string", "description": "Ticker symbol, e.g. AAPL, NVDA, BTCUSD."},
					"limit":  map[string]any{"type": "integer", "description": "Optional row cap (for news/earnings/filings). Default 10, max 50."},
				},
				"required": []string{"kind", "symbol"},
			},
		},
		{
			"name":        "remember_about_me",
			"description": "Save a fact, preference, or working-style note about the user to long-term memory. Use whenever the user explicitly shares something they want you to remember (\"I prefer terse summaries\", \"my main symbol is NVDA\", \"never ping me before 9am\"). Each call appends one row to the me-prefs knowledge bank; recent rows are injected into your system prompt on every subsequent chat, so saved facts shape future replies automatically. Do NOT use for ephemeral session state.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"note": map[string]any{"type": "string", "description": "The fact or preference, in the user's own framing when possible. One sentence ideal."},
					"tags": map[string]any{"type": "string", "description": "Optional comma-separated retrieval hints, e.g. 'preference,style' or 'fact,trading'."},
				},
				"required": []string{"note"},
			},
		},
		{
			"name":        "code_run",
			"description": "Run a short Python 3 snippet in a sandboxed environment and return stdout/stderr/exit_code. Use for math/data calculations, CSV/JSON parsing, quick chart-style aggregation, or any task that's easier to compute than describe. The sandbox is network-isolated, capped at 30s CPU + 512MB memory + 10MB file output, and runs as 'nobody' with no host filesystem access. The standard library is available; no third-party packages.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code":        map[string]any{"type": "string", "description": "Python 3 source. Use print() to emit results — only stdout/stderr are returned."},
					"timeout_sec": map[string]any{"type": "integer", "description": "Optional wall-clock timeout, default 30, max 60."},
				},
				"required": []string{"code"},
			},
		},
		{
			"name":        "send_email",
			"description": "Send an email from the user's connected Gmail account. The user must have linked Google at /dashboard/account/connect/google (the same OAuth grant that powers personal-agent); if not, the tool returns a clean error pointing them there. ALWAYS read back the subject + recipients in your reply so the user can confirm what was sent. Use plain text bodies — markdown won't render in email.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to":      map[string]any{"type": "string", "description": "Comma-separated recipient(s). Required."},
					"subject": map[string]any{"type": "string", "description": "Email subject line. Required, max ~80 chars ideal."},
					"body":    map[string]any{"type": "string", "description": "Plain text body. Required."},
					"cc":      map[string]any{"type": "string", "description": "Optional comma-separated CC recipients."},
					"bcc":     map[string]any{"type": "string", "description": "Optional comma-separated BCC recipients."},
				},
				"required": []string{"to", "subject", "body"},
			},
		},
		{
			"name":        "create_calendar_event",
			"description": "Create an event on the user's primary Google Calendar. Requires Google connected at /dashboard/account/connect/google. Use ISO-8601 datetimes with offsets (2026-06-01T14:00:00-07:00) for timed events, or YYYY-MM-DD strings for all-day events. Confirm details (title, when, who) back to the user in your reply.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string", "description": "Event title. Required."},
					"start":       map[string]any{"type": "string", "description": "ISO 8601 datetime OR YYYY-MM-DD for all-day. Required."},
					"end":         map[string]any{"type": "string", "description": "ISO 8601 datetime OR YYYY-MM-DD. Required."},
					"description": map[string]any{"type": "string", "description": "Optional details. Plain text."},
					"location":    map[string]any{"type": "string", "description": "Optional location or videoconf URL."},
					"attendees":   map[string]any{"type": "string", "description": "Optional comma-separated email list. Invitations are sent automatically."},
					"timezone":    map[string]any{"type": "string", "description": "Optional IANA timezone for timed events, e.g. 'America/Los_Angeles'. Defaults to America/Los_Angeles."},
				},
				"required": []string{"title", "start", "end"},
			},
		},
		{
			"name":        "spawn_agent",
			"description": "Delegate a focused job to a sub-agent. The sub-agent runs its own short tool-use loop (max 5 iterations, 45s) with a curated tool subset, and returns its final reply. Use this when a research-heavy or analysis-heavy sub-task would otherwise clutter your own context with many tool calls — e.g. 'spawn a sub-agent to investigate X across 5 sources and return a 3-paragraph brief'. The sub-agent gets a fresh message history; it doesn't see this conversation. By default the sub-agent gets read-only + research tools (web_search, web_fetch, deep_research, query_findata, query_my_knowledge, code_run, list_*, today_summary). To restrict further, pass tools=[...].",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task":     map[string]any{"type": "string", "description": "The focused job, in natural language. Include enough context for a fresh agent to understand."},
					"tools":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional whitelist of tool names the sub-agent may use. Defaults to a read-only + research subset."},
					"agent_id": map[string]any{"type": "string", "description": "Optional xpio agent id to ground the sub-agent in (same effect as the user's agent picker — see /me/agents)."},
					"max_iter": map[string]any{"type": "integer", "description": "Optional cap on tool-use iterations, default 5, max 5."},
				},
				"required": []string{"task"},
			},
		},
		{
			"name":        "spawn_agents",
			"description": "Run several sub-agents IN PARALLEL and get all their replies back together. Use this when you have multiple independent sub-tasks (e.g. research 4 companies, audit 3 files) — they execute concurrently (up to 4 at once, 6 tasks max) instead of one-after-another. Each task is like a spawn_agent call: fresh history, read-only + research tools by default. Returns {agents: [{task, reply, tool_calls, error?}]}.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"tasks": map[string]any{
						"type":        "array",
						"description": "Up to 6 tasks. Each item is either a task string, or an object {task, tools?, agent_id?}.",
						"items":       map[string]any{"type": "object"},
					},
				},
				"required": []string{"tasks"},
			},
		},
		{
			"name":        "save_artifact",
			"description": "Save a piece of output (markdown brief, code listing, JSON dataset, plain text) as a persistent artifact in the user's tenant. The artifact appears in the Studio artifact panel and survives across sessions. Use this when the chat produces a long-form deliverable the user is likely to revisit: a research brief from deep_research, a generated script from code_run, a structured summary they asked you to compile. Always set a clear `title` (e.g. 'AAPL Q1 earnings brief' — not 'untitled'). The returned `id` + `url` can be referenced in follow-up turns.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string", "description": "Human-readable name for the artifact, max ~80 chars ideal."},
					"content":     map[string]any{"type": "string", "description": "Body of the artifact. Plain text, markdown, code, or JSON — match the `kind`."},
					"kind":        map[string]any{"type": "string", "enum": []string{"markdown", "code", "json", "text"}, "description": "Rendering hint. Default: markdown."},
					"language":    map[string]any{"type": "string", "description": "For kind=code: source language (python, go, js, sql, …)."},
					"source_tool": map[string]any{"type": "string", "description": "Optional — which prior tool produced this content (e.g. deep_research, code_run). Surfaces as a badge in the panel."},
				},
				"required": []string{"title", "content"},
			},
		},
		// ── File tools (path-jailed per user role) ──────────────────────────
		{
			"name":        "read_file",
			"description": "Read a file. admin/super_admin can read the /proj deployment tree (and their own app bundles); other users read their own tenant workspace. Path is relative to the workspace root.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Relative path within workspace, e.g. 'auto-quant/xpcloud.yaml'."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "write_file",
			"description": "Write content to a file in your own workspace (super_admin: the /proj tree; everyone else: their own tenant workspace — never /proj). Creates parent directories as needed. Requires approval. Path is relative to the workspace root.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string", "description": "Relative path within workspace."},
					"content": map[string]any{"type": "string", "description": "File content to write."},
				},
				"required": []string{"path", "content"},
			},
		},
		{
			"name":        "edit_file",
			"description": "Replace old_string with new_string in an existing file in your workspace. By default replaces the first occurrence; set replace_all=true for every occurrence. Requires approval. Path is relative to the workspace root.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":        map[string]any{"type": "string"},
					"old_string":  map[string]any{"type": "string", "description": "Exact text to find (must be unique enough to identify the right location, unless replace_all)."},
					"new_string":  map[string]any{"type": "string", "description": "Replacement text."},
					"replace_all": map[string]any{"type": "boolean", "description": "Replace every occurrence instead of just the first. Default false."},
				},
				"required": []string{"path", "old_string", "new_string"},
			},
		},
		{
			"name":        "multi_edit",
			"description": "Apply several find/replace edits to ONE file atomically — every old_string must match or nothing is written. Use this instead of multiple edit_file calls when changing several spots in the same file. Requires approval. Path is relative to the workspace root.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
					"edits": map[string]any{
						"type":        "array",
						"description": "Ordered list of edits, each applied to the result of the previous.",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"old_string":  map[string]any{"type": "string"},
								"new_string":  map[string]any{"type": "string"},
								"replace_all": map[string]any{"type": "boolean", "description": "Replace every occurrence of this edit's old_string. Default false."},
							},
							"required": []string{"old_string", "new_string"},
						},
					},
				},
				"required": []string{"path", "edits"},
			},
		},
		{
			"name":        "glob_files",
			"description": "Find files in your workspace whose path matches a glob pattern. Supports '*.go', '**/*.yaml' (any directory), 'dir/*.py'. Read-only. Returns relative paths.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":     map[string]any{"type": "string", "description": "Glob, e.g. '**/*.go' or 'configs/*.yaml'."},
					"max_results": map[string]any{"type": "integer", "description": "Cap on results (default 300, max 1000)."},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name":        "grep_files",
			"description": "Search file CONTENTS in your workspace for a regular expression. Read-only. Returns matching lines as {path, line, text}. Optionally restrict to files matching path_glob.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":     map[string]any{"type": "string", "description": "Go regexp (RE2) to search for, e.g. 'func .*Handler'."},
					"path_glob":   map[string]any{"type": "string", "description": "Optional glob limiting which files to scan, e.g. '**/*.go'."},
					"max_results": map[string]any{"type": "integer", "description": "Cap on matching lines (default 100, max 500)."},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name":        "bash_exec",
			"description": "Execute a bash command in your workspace. super_admin: runs in the /proj tree. Everyone else: runs in an isolated Docker sandbox — no network, your workspace mounted at /workspace, capped CPU/memory. Requires approval. Foreground max 120s. For long-running work (builds, batch jobs) set background=true: returns a task_id immediately and runs up to 30 minutes; check progress later with list_tasks / task_output.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":         map[string]any{"type": "string", "description": "Bash command to run."},
					"timeout_seconds": map[string]any{"type": "integer", "description": "Foreground: 1-120s (default 30). Background: 1-1800s (default 600)."},
					"background":      map[string]any{"type": "boolean", "description": "Run detached; returns {task_id} immediately. Default false."},
				},
				"required": []string{"command"},
			},
		},
		{
			"name":         "list_tasks",
			"description":  "List your background bash tasks (from bash_exec with background=true): id, status (running|done|error|timeout), command, started/finished times, exit code.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "task_output",
			"description": "Fetch the captured output of one background task by task_id. While a sandboxed (non-operator) task is still running its output arrives only on completion; operator tasks stream incrementally.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task_id": map[string]any{"type": "string"},
				},
				"required": []string{"task_id"},
			},
		},
		// ── LumidOS ops tools (proxied to schedule server :9100) ────────────
		{
			"name":         "xp_status",
			"description":  "Return the status of the local XP.io knowledge graph: which agents exist, memory counts, last sync.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "xp_ask",
			"description": "Query the XP.io knowledge graph with a natural-language question. Returns memories ranked by relevance.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"question": map[string]any{"type": "string"},
					"agent_id": map[string]any{"type": "string", "description": "Optional: scope to a specific agent."},
					"strategy": map[string]any{"type": "string", "description": "route | direct | broadcast. Default: route."},
				},
				"required": []string{"question"},
			},
		},
		{
			"name":         "xp_agents",
			"description":  "List all XP.io knowledge agents on this host.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "xp_memories",
			"description": "Return recent memories for a specific XP.io agent.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"agent_id": map[string]any{"type": "string"}},
				"required":   []string{"agent_id"},
			},
		},
		{
			"name":        "xp_ingest",
			"description": "Add a new memory (action/context/outcome triple) to an XP.io agent's knowledge bank. Requires approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id": map[string]any{"type": "string"},
					"context":  map[string]any{"type": "string"},
					"action":   map[string]any{"type": "string"},
					"outcome":  map[string]any{"type": "string"},
				},
				"required": []string{"agent_id"},
			},
		},
		{
			"name":        "xp_feedback",
			"description": "Apply a reward signal to a specific memory to improve retrieval ranking.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":  map[string]any{"type": "string"},
					"memory_id": map[string]any{"type": "string"},
					"reward":    map[string]any{"type": "number"},
				},
				"required": []string{"agent_id", "memory_id", "reward"},
			},
		},
		{
			"name":        "xp_new_agent",
			"description": "Create a new XP.io knowledge agent.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":    map[string]any{"type": "string"},
					"domain":      map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
				},
				"required": []string{"agent_id", "domain", "description"},
			},
		},
		{
			"name":        "xp_subscribe",
			"description": "Subscribe a local agent to a remote knowledge agent on xp.io to receive new memories.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target_agent": map[string]any{"type": "string"},
					"source_slug":  map[string]any{"type": "string"},
				},
				"required": []string{"target_agent", "source_slug"},
			},
		},
		{
			"name":         "xp_remotes",
			"description":  "List remote knowledge agents this host subscribes to.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "xp_share",
			"description": "Push a local knowledge agent's bank to xp.io cloud.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"agent_id": map[string]any{"type": "string"}},
				"required":   []string{"agent_id"},
			},
		},
		{
			"name":        "xp_pull",
			"description": "Pull updates from a remote knowledge agent into the local bank.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"agent_id": map[string]any{"type": "string"}},
				"required":   []string{"agent_id"},
			},
		},
		{
			"name":        "xp_clone",
			"description": "Clone a remote knowledge agent from xp.io to this host.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":   map[string]any{"type": "string"},
					"remote_url": map[string]any{"type": "string"},
				},
				"required": []string{"agent_id", "remote_url"},
			},
		},
		{
			"name":        "xp_learn",
			"description": "Add a text observation directly to the knowledge bank.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text":     map[string]any{"type": "string"},
					"agent_id": map[string]any{"type": "string"},
				},
				"required": []string{"text"},
			},
		},
		{
			"name":        "xp_marketplace",
			"description": "Browse published knowledge agents on xp.io.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain": map[string]any{"type": "string"},
					"q":      map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":         "list_loops",
			"description":  "HOST/operator-scope: scheduled jobs on the LumidOS schedule server (not the caller's apps). For the USER's own installed app workflows and their health/last-run/status, use list_workflows or loops_health instead — those are tenant-scoped and are what 'my workflows / my autoresearch' refers to.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "loop_status",
			"description": "Get detailed status for a specific research loop, including recent cycle history.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
					"app":  map[string]any{"type": "string", "description": "Optional: parent app name."},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "run_loop",
			"description": "Trigger a research loop to run immediately (outside its normal schedule). For firing a one-off run of an installed app's workflow, prefer run_loop_now (app+loop).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":   map[string]any{"type": "string"},
					"cycles": map[string]any{"type": "integer", "description": "How many cycles to run, default 1."},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "loop_history",
			"description": "Return the last N cycle results for a research loop.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
					"last": map[string]any{"type": "integer", "description": "Default 10."},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":         "agent_list",
			"description":  "List all xpio agents installed on this host.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			// Alias of agent_list (legacy name). Kept so in-flight clients/prompts
			// calling app_list keep working; both dispatch to the same op.
			"name":         "app_list",
			"description":  "Alias of agent_list (legacy name). List all xpio agents installed on this host.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "agent_marketplace",
			"description": "Browse the xp.io agent marketplace.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":    map[string]any{"type": "string"},
					"kind": map[string]any{"type": "string", "description": "agent | skill | workflow | dataset | memory. Default: agent."},
				},
			},
		},
		{
			"name":        "app_marketplace",
			"description": "Alias of agent_marketplace (legacy name). Browse the xp.io agent marketplace.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":    map[string]any{"type": "string"},
					"kind": map[string]any{"type": "string", "description": "agent | skill | workflow | dataset | memory. Default: agent."},
				},
			},
		},
		{
			"name":        "agent_detail",
			"description": "Get metadata and schema for a specific xpio agent from the marketplace.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"slug": map[string]any{"type": "string"}},
				"required":   []string{"slug"},
			},
		},
		{
			"name":        "app_detail",
			"description": "Alias of agent_detail (legacy name). Get metadata and schema for a specific xpio agent from the marketplace.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"slug": map[string]any{"type": "string"}},
				"required":   []string{"slug"},
			},
		},
		{
			"name":        "agent_install",
			"description": "Install an xpio agent from xp.io to this host.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":     map[string]any{"type": "string"},
					"new_name": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "app_install",
			"description": "Alias of agent_install (legacy name). Install an xpio agent from xp.io to this host.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":     map[string]any{"type": "string"},
					"new_name": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "list_experiments",
			"description": "List an app's declared experiments: hypothesis, kind (regression/explore/arms), sample count, best variant vs baseline, and whether success criteria are met.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "experiment_status",
			"description": "Detailed state for one experiment: per-variant aggregates, delta vs baseline, per-case score history (casebook experiments), and verdict.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string"},
					"id":  map[string]any{"type": "string"},
				},
				"required": []string{"app", "id"},
			},
		},
		{
			"name":        "fork_app",
			"description": "Fork an installed app into the user's own xp.io repo and install the fork so they can edit it. Use when the user wants to customize a showcase app or 'make it their own'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "installed app slug"},
					"name": map[string]any{"type": "string", "description": "optional new name for the fork"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "publish_app",
			"description": "Publish the user's local changes of THEIR app (a fork or composed app) to their xp.io repo. Use when the user says 'publish my app/changes'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":     map[string]any{"type": "string"},
					"summary": map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "propose_upstream",
			"description": "Open a pull request proposing the user's published fork changes to the upstream app. Use when the user wants to contribute changes back.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string"},
					"title": map[string]any{"type": "string"},
					"body":  map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "agent_push",
			"description": "Push a local xpio agent to xp.io (publish / update). Auto-bumps patch version if content changed. Requires approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":    map[string]any{"type": "string"},
					"message": map[string]any{"type": "string"},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "app_push",
			"description": "Alias of agent_push (legacy name). Push a local xpio agent to xp.io (publish / update). Auto-bumps patch version if content changed. Requires approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":    map[string]any{"type": "string"},
					"message": map[string]any{"type": "string"},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "agent_validate",
			"description": "Validate an installed xpio agent's manifest and config before pushing.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string"}},
				"required":   []string{"name"},
			},
		},
		{
			"name":        "app_validate",
			"description": "Alias of agent_validate (legacy name). Validate an installed xpio agent's manifest and config before pushing.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string"}},
				"required":   []string{"name"},
			},
		},
		{
			"name":        "agent_update",
			"description": "Pull the latest version of an installed agent from xp.io.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string"}},
				"required":   []string{"name"},
			},
		},
		{
			"name":        "app_update",
			"description": "Alias of agent_update (legacy name). Pull the latest version of an installed agent from xp.io.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string"}},
				"required":   []string{"name"},
			},
		},
		{
			"name":        "submit_workflow",
			"description": "Submit a FlowMesh workflow YAML for execution on the GPU cluster. Requires approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"workflow_yaml": map[string]any{"type": "string", "description": "Full workflow YAML string."},
				},
				"required": []string{"workflow_yaml"},
			},
		},
		{
			"name":         "list_workers",
			"description":  "List available FlowMesh compute workers and their current status.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "optimize_workflow",
			"description": "Run the HALO optimizer on a workflow YAML to get an optimized execution plan (dry run, no execution).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"workflow_yaml": map[string]any{"type": "string"},
				},
				"required": []string{"workflow_yaml"},
			},
		},
	}
}

// dispatchTool routes the agent's tool calls into local /me/* logic.
// Returns (result, ok). result is always a JSON-able map; on failure
// it contains {"error": "..."} and ok is false.
func dispatchTool(c *gin.Context, userID, role, name string, args map[string]any) (map[string]any, bool) {
	// Approval backstop — destructive tools must NOT execute unless they were
	// approved. The streaming handler runs the interactive approval gate and
	// then sets "approved_tool" on the context before calling us; an "always
	// allow" grant also clears them. Any OTHER caller (the non-streaming
	// /me/agent/chat endpoint, the sub-agent loop) reaches here without that
	// marker — fail closed so a mutating tool can never run unconsented,
	// regardless of transport. This is enforcement-at-the-sink; the per-
	// transport gate stays for the interactive UX.
	if destructiveTools[name] {
		approved, _ := c.Get("approved_tool")
		if approved != name && !hasToolGrant(userID, name) {
			log.Printf("[me-agent] BLOCKED destructive tool=%q user=%s — no approval on this path", name, userID)
			return map[string]any{"error": "this action requires explicit user approval, which was not granted on this request"}, false
		}
	}
	switch name {
	case "list_apps":
		return toolListApps(userID), true

	case "install_app":
		slug, _ := args["slug"].(string)
		asName, _ := args["as"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		id := writeIntentDirect(userID, "install", map[string]any{
			"slug": slug, "runtime": "local", "as": asName,
		})
		if id == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{"intent_id": id, "status": "pending", "note": "Tell the user the install is in progress; it usually finishes in 5-15 seconds."}, true

	case "uninstall_app":
		app, _ := args["app"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		id := writeIntentDirect(userID, "uninstall", map[string]any{"app": app})
		if id == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{"intent_id": id, "status": "pending"}, true

	case "list_experiments":
		app, _ := args["app"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		dir := resolveAppDir(userID, app)
		if dir == "" {
			return map[string]any{"error": "app not installed"}, false
		}
		exps := loadAppExperiments(dir)
		return map[string]any{"experiments": exps, "count": len(exps)}, true

	case "experiment_status":
		app, _ := args["app"].(string)
		id, _ := args["id"].(string)
		if app == "" || id == "" {
			return map[string]any{"error": "app and id required"}, false
		}
		dir := resolveAppDir(userID, app)
		if dir == "" {
			return map[string]any{"error": "app not installed"}, false
		}
		detail, found := loadExperimentDetail(dir, id)
		if !found {
			return map[string]any{"error": "experiment not found"}, false
		}
		// keep the tool result compact for the model: drop raw rows
		delete(detail, "results")
		return map[string]any(detail), true

	case "fork_app":
		app, _ := args["app"].(string)
		name, _ := args["name"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		if name == "" {
			name = app
		}
		bearer, err := xpcloudUserJWT(userID)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		upstream := appUpstreamSlug(userID, app)
		code, resp, err := xpcloudJSON(http.MethodPost,
			xpcloudBaseURL()+"/api/v1/repos/"+upstream+"/fork", bearer,
			map[string]any{"name": name})
		if err != nil || code >= 300 {
			return map[string]any{"error": fmt.Sprintf("fork failed (%d): %v %v", code, resp["detail"], err)}, false
		}
		iid := writeIntentDirect(userID, "install", map[string]any{"slug": userID + "/" + name, "as": name, "bearer": bearer})
		return map[string]any{"fork": userID + "/" + name, "upstream": upstream, "install_intent": iid,
			"repo_url": "https://xp.io/" + userID + "/" + name}, true

	case "publish_app":
		app, _ := args["app"].(string)
		summary, _ := args["summary"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		bearer, err := xpcloudUserJWT(userID)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		iid := writeIntentDirect(userID, "publish_app", map[string]any{"app": app, "summary": summary, "bearer": bearer})
		if iid == "" {
			return map[string]any{"error": "queue publish intent failed"}, false
		}
		return map[string]any{"intent_id": iid, "state": "queued",
			"repo_url": "https://xp.io/" + userID + "/" + app}, true

	case "propose_upstream":
		app, _ := args["app"].(string)
		title, _ := args["title"].(string)
		prBody, _ := args["body"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		if title == "" {
			title = "Changes from fork of " + app
		}
		bearer, err := xpcloudUserJWT(userID)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		upstream := ""
		if code, meta, e := xpcloudJSON(http.MethodGet, xpcloudBaseURL()+"/api/v1/repos/"+userID+"/"+app, bearer, nil); e == nil && code == 200 {
			if fo, _ := meta["fork_of"].(string); fo != "" {
				upstream = fo
			}
		}
		if upstream == "" {
			upstream = appUpstreamSlug(userID, app)
		}
		code, resp, err := xpcloudJSON(http.MethodPost,
			xpcloudBaseURL()+"/api/v1/repos/"+upstream+"/pulls", bearer,
			map[string]any{"title": title, "body": prBody, "head_owner": userID,
				"head_name": app, "head_branch": "main", "base_branch": "main"})
		if err != nil || code >= 300 {
			return map[string]any{"error": fmt.Sprintf("propose failed (%d): %v %v", code, resp["detail"], err)}, false
		}
		return map[string]any{"upstream": upstream, "pull": resp["pr"],
			"pulls_url": "https://xp.io/" + upstream + "/pulls"}, true

	case "run_loop_now":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		if app == "" || loop == "" {
			return map[string]any{"error": "app and loop required"}, false
		}
		// Optional run scope → threaded as args.cases (the loop template
		// expands {{ args.cases }}); empty = full set.
		var oneshotArgs map[string]any
		if cases, _ := args["cases"].(string); cases != "" {
			oneshotArgs = map[string]any{"cases": cases}
		}
		jobID, err := agentEnqueueOneshot(userID, app, loop, oneshotArgs)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"job_id": jobID, "state": "queued"}, true

	case "stop_loop":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		if app == "" || loop == "" {
			return map[string]any{"error": "app and loop required"}, false
		}
		stopped, err := agentStopLoop(userID, app, loop)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"app": app, "loop": loop, "stopped_cycle": stopped, "state": "stopping"}, true

	case "cycle_detail":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		ts, _ := args["ts"].(string)
		return toolCycleDetail(userID, app, loop, ts)

	case "loops_health":
		return toolLoopsHealth(userID)

	case "review_action":
		return toolReviewAction(userID, args)

	case "experiment_case":
		app, _ := args["app"].(string)
		id, _ := args["id"].(string)
		caseID, _ := args["case_id"].(string)
		return toolExperimentCase(userID, app, id, caseID)

	case "loop_metric_series":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		return toolLoopMetricSeries(userID, app, loop)

	case "casebook":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		return toolCasebook(userID, app, loop)

	case "app_feedback":
		app, _ := args["app"].(string)
		note, _ := args["note"].(string)
		rating := 0
		if v, ok := args["rating"].(float64); ok {
			rating = int(v)
		}
		return toolAppFeedback(userID, app, note, rating)

	case "app_answer":
		app, _ := args["app"].(string)
		question, _ := args["question"].(string)
		caseID, _ := args["case_id"].(string)
		return toolAppAnswer(c.Request.Context(), userID, role, app, question, caseID)

	case "app_judge":
		app, _ := args["app"].(string)
		answer, _ := args["answer"].(string)
		question, _ := args["question"].(string)
		caseID, _ := args["case_id"].(string)
		// The mode decides whether MISSED keypoints come back: the interviewer
		// owns the case and may see them; the candidate must not.
		return toolAppJudge(c.Request.Context(), userID, role, app, caseID, question, answer, c.GetString(ctxModeKey))

	case "app_config_get":
		app, _ := args["app"].(string)
		return toolAppConfigGet(userID, app)

	case "app_config_set":
		return toolAppConfigSet(userID, args)

	case "knowledge_agents":
		return toolKnowledgeAgents(userID)

	case "knowledge_memories":
		agent, _ := args["agent"].(string)
		limit := 0
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return toolKnowledgeMemories(userID, agent, limit)

	case "give_feedback":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		ts, _ := args["ts"].(string)
		note, _ := args["note"].(string)
		rating := 0
		if v, ok := args["rating"].(float64); ok {
			rating = int(v)
		}
		if app == "" || loop == "" || ts == "" {
			return map[string]any{"error": "app/loop/ts required"}, false
		}
		if ts == "latest" {
			resolved, err := agentLatestCycleTs(userID, app, loop)
			if err != nil {
				return map[string]any{"error": "no recent cycles for " + app + "." + loop}, false
			}
			ts = resolved
		}
		if err := agentWriteFeedback(userID, app, loop, ts, rating, note); err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"saved": true, "app": app, "loop": loop, "ts": ts}, true

	case "list_recent_cycles":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		limit := 5
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		return map[string]any{"cycles": agentListCycles(userID, app, loop, limit)}, true

	case "intent_audit":
		app, _ := args["app"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		loop, _ := args["loop"].(string)
		since, _ := args["since"].(string)
		if since == "" {
			since = "7d"
		}
		limit := 30
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		events, err := readImprovements(userID, app, loop, since, limit)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{
			"intent_id":      app,
			"loop":           loop,
			"since":          since,
			"event_count":    len(events),
			"axis_movements": summarizeImprovements(events),
			"events":         events,
		}, true

	case "list_marketplace":
		q, _ := args["q"].(string)
		limit := 10
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		return map[string]any{"items": agentListMarketplace(q, limit)}, true

	case "query_my_knowledge":
		query, _ := args["query"].(string)
		agent, _ := args["agent"].(string)
		limit := 6
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		if query == "" {
			return map[string]any{"error": "query required"}, false
		}
		hits := agentQueryKnowledge(userID, query, agent, limit)
		return map[string]any{"hits": hits, "count": len(hits)}, true

	case "subscribe_to_bank":
		src, _ := args["source_slug"].(string)
		target, _ := args["target_agent_id"].(string)
		if src == "" {
			return map[string]any{"error": "source_slug required"}, false
		}
		intentID := writeIntentDirect(userID, "subscribe_bank", map[string]any{
			"source_slug":     src,
			"target_agent_id": target,
		})
		if intentID == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{
			"intent_id": intentID,
			"status":    "pending",
			"note":      "Subscribe queued — memories will flow on the next cycle. Tell the user it may take a moment.",
		}, true

	// ── Phase S6c new tools ────────────────────────────────────────

	case "today_summary":
		return toolTodaySummary(userID), true

	case "list_drafts":
		app, _ := args["app"].(string)
		return toolListDrafts(userID, app), true

	case "send_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		return toolDraftAction(userID, id, "send", nil), true

	case "dismiss_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		return toolDraftAction(userID, id, "dismiss", nil), true

	case "edit_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		body, _ := args["body"].(string)
		subject, _ := args["subject"].(string)
		patch := map[string]any{}
		if body != "" {
			patch["body"] = body
		}
		if subject != "" {
			patch["subject"] = subject
		}
		if len(patch) == 0 {
			return map[string]any{"error": "provide body or subject"}, false
		}
		return toolDraftAction(userID, id, "edit", patch), true

	case "patch_loop":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		if app == "" || loop == "" {
			return map[string]any{"error": "app and loop required"}, false
		}
		patch := map[string]any{}
		if v, ok := args["schedule"].(string); ok && v != "" {
			patch["schedule"] = v
		}
		if v, ok := args["enabled"].(bool); ok {
			patch["enabled"] = v
		}
		if len(patch) == 0 {
			return map[string]any{"error": "provide schedule or enabled"}, false
		}
		return toolPatchLoop(userID, app, loop, patch), true

	// ── Workflow surface (W1) — delegate to MeWorkflows / MeRuns
	// handlers via thin Go wrappers that bypass the HTTP layer.
	case "list_workflows":
		kind, _ := args["kind"].(string)
		return toolListWorkflows(c, userID, kind), true

	case "workflow_detail":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolWorkflowDetail(c, userID, slug), true

	case "list_runs":
		state, _ := args["state"].(string)
		workflow, _ := args["workflow"].(string)
		limit := 25
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return toolListRuns(c, userID, state, workflow, limit), true

	case "run_detail":
		runID, _ := args["run_id"].(string)
		if runID == "" {
			return map[string]any{"error": "run_id required"}, false
		}
		return toolRunDetail(c, userID, runID), true

	case "pause_workflow":
		slug, _ := args["slug"].(string)
		enabled, _ := args["enabled"].(bool)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		// scheduled workflows only — slug shape "<app>:<loop>".
		parts := strings.SplitN(slug, ":", 2)
		if len(parts) != 2 || parts[0] == "n8n" {
			return map[string]any{"error": "pause_workflow only supports scheduled workflows (slug '<app>:<loop>'); use n8n's UI to toggle visual workflows"}, false
		}
		return toolPatchLoop(userID, parts[0], parts[1], map[string]any{"enabled": enabled}), true

	// ── Create surface (W2) ───────────────────────────────────
	case "search_marketplace":
		query, _ := args["query"].(string)
		forApp, _ := args["for_app"].(string)
		limit := 5
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		// An empty query is a BROWSE, not an error — toolSearchMarketplace
		// returns a catalog listing when query=="". Erroring on missing query
		// made models (notably gemma4, which often fires search_marketplace
		// with no args for "what's available" intents) report a tool error;
		// browsing the catalog is the right, useful behavior.
		return toolSearchMarketplace(c, query, forApp, limit), true

	case "compose_workflow":
		intent, _ := args["intent"].(string)
		forApp, _ := args["for_app"].(string)
		name, _ := args["name"].(string)
		if intent == "" {
			return map[string]any{"error": "intent required"}, false
		}
		return toolComposeWorkflow(c, userID, intent, forApp, name), true

	case "add_skill_to_workflow":
		slug, _ := args["slug"].(string)
		skillName, _ := args["skill_name"].(string)
		if slug == "" || skillName == "" {
			return map[string]any{"error": "slug and skill_name required"}, false
		}
		return toolAddSkillToWorkflow(userID, slug, skillName), true

	// ── Improve surface (W4) ──────────────────────────────────
	case "workflow_report_card":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolWorkflowReportCard(c, userID, slug), true

	case "trigger_evaluation":
		skillName, _ := args["skill_name"].(string)
		forApp, _ := args["for_app"].(string)
		if skillName == "" || forApp == "" {
			return map[string]any{"error": "skill_name and for_app required"}, false
		}
		return toolTriggerEvaluation(userID, skillName, forApp), true

	case "suggest_workflow_improvement":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolSuggestImprovement(c, userID, slug), true

	case "web_search":
		query, _ := args["query"].(string)
		num := 0
		if v, ok := args["num_results"].(float64); ok {
			num = int(v)
		}
		return toolWebSearch(query, num)

	case "web_fetch":
		url, _ := args["url"].(string)
		return toolWebFetch(url)

	case "deep_research":
		question, _ := args["question"].(string)
		maxResults := 0
		if v, ok := args["max_results"].(float64); ok {
			maxResults = int(v)
		}
		return toolDeepResearch(question, maxResults)

	case "query_findata":
		kind, _ := args["kind"].(string)
		symbol, _ := args["symbol"].(string)
		limit := 0
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return toolQueryFindata(kind, symbol, limit)

	case "remember_about_me":
		note, _ := args["note"].(string)
		return toolRememberAboutMe(userID, note, args["tags"])

	case "code_run":
		code, _ := args["code"].(string)
		timeout := 0
		if v, ok := args["timeout_sec"].(float64); ok {
			timeout = int(v)
		}
		return toolCodeRun(code, timeout)

	case "save_artifact":
		return toolSaveArtifact(userID, args)

	case "spawn_agent":
		return toolSpawnAgent(c, userID, args)

	case "send_email":
		return toolSendEmail(userID, args)

	case "create_calendar_event":
		return toolCreateCalendarEvent(userID, args)

	// ── File tools ────────────────────────────────────────────────────────
	case "read_file":
		path, _ := args["path"].(string)
		if path == "" {
			return map[string]any{"error": "path required"}, false
		}
		return toolReadFile(userID, role, path)

	// write_file / edit_file / multi_edit / bash_exec are open to ALL roles.
	// Isolation is NOT enforced by the role here — it's enforced structurally
	// by the jail: writeRoot(userID, role) confines writes to the caller's own
	// tenant workspace (super_admin → /proj), and bash runs non-super in a
	// network-free Docker sandbox mounting only that workspace. So every user
	// gets the full toolset, scoped to their own space.
	case "write_file":
		path, _ := args["path"].(string)
		content, _ := args["content"].(string)
		if path == "" {
			return map[string]any{"error": "path required"}, false
		}
		return toolWriteFile(userID, role, path, content)

	case "edit_file":
		path, _ := args["path"].(string)
		oldStr, _ := args["old_string"].(string)
		newStr, _ := args["new_string"].(string)
		replaceAll, _ := args["replace_all"].(bool)
		if path == "" {
			return map[string]any{"error": "path required"}, false
		}
		if oldStr == "" {
			return map[string]any{"error": "old_string required (empty old_string would prepend to file)"}, false
		}
		return toolEditFile(userID, role, path, oldStr, newStr, replaceAll)

	case "multi_edit":
		path, _ := args["path"].(string)
		if path == "" {
			return map[string]any{"error": "path required"}, false
		}
		rawEdits, _ := args["edits"].([]any)
		edits := make([]editOp, 0, len(rawEdits))
		for _, r := range rawEdits {
			m, _ := r.(map[string]any)
			if m == nil {
				continue
			}
			old, _ := m["old_string"].(string)
			ns, _ := m["new_string"].(string)
			ra, _ := m["replace_all"].(bool)
			edits = append(edits, editOp{OldString: old, NewString: ns, ReplaceAll: ra})
		}
		return toolMultiEdit(userID, role, path, edits)

	case "glob_files":
		pattern, _ := args["pattern"].(string)
		max := 0
		if v, ok := args["max_results"].(float64); ok {
			max = int(v)
		}
		return toolGlobFiles(userID, role, pattern, max)

	case "grep_files":
		pattern, _ := args["pattern"].(string)
		if pattern == "" {
			return map[string]any{"error": "pattern required"}, false
		}
		pathGlob, _ := args["path_glob"].(string)
		max := 0
		if v, ok := args["max_results"].(float64); ok {
			max = int(v)
		}
		return toolGrepFiles(userID, role, pattern, pathGlob, max)

	case "bash_exec":
		command, _ := args["command"].(string)
		if command == "" {
			return map[string]any{"error": "command required"}, false
		}
		timeout := 30
		if v, ok := args["timeout_seconds"].(float64); ok {
			timeout = int(v)
		}
		if bg, _ := args["background"].(bool); bg {
			return startBackgroundBash(userID, role, command, timeout)
		}
		return toolBashExec(userID, role, command, timeout)

	case "list_tasks":
		return toolListTasks(userID), true

	case "task_output":
		taskID, _ := args["task_id"].(string)
		return toolTaskOutput(userID, taskID)

	case "spawn_agents":
		return toolSpawnAgents(c, userID, args)
	}

	// ── Admin control-plane tools (admin/super_admin only) ────────────────
	switch name {
	case "admin_users":
		return toolAdminUsersList(role, args)
	case "admin_set_user_role":
		return toolAdminUsersSet(c, userID, role, "role", args)
	case "admin_set_user_status":
		return toolAdminUsersSet(c, userID, role, "status", args)
	case "admin_grant_access":
		return toolAdminGrantAccess(c, userID, role, args)
	case "admin_clusters":
		return toolAdminClusters(userID, role, args)
	case "admin_set_worker_pricing":
		return toolAdminSetWorkerPricing(userID, role, args)
	case "operator_healthcheck":
		dimension, _ := args["dimension"].(string)
		return toolOperatorHealthcheck(c, userID, role, dimension)
	case "operator_remediate":
		dimension, _ := args["dimension"].(string)
		dryRun, _ := args["dry_run"].(bool)
		return toolOperatorRemediate(c, userID, role, dimension, dryRun)
	case "account_list_pat":
		return toolAccountListPat(userID)
	case "account_revoke_pat":
		return toolAccountRevokePat(c, userID, args)
	case "account_set_profile":
		return toolAccountSetProfile(c, userID, args)
	case "delete_loop":
		return toolDeleteLoop(userID, args)
	case "generate_image":
		return toolGenerateImage(c.Request.Context(), userID, args)
	case "text_to_speech":
		return toolTextToSpeech(c.Request.Context(), userID, args)
	}

	// ── Generic app-ops bridge (operate any app from chat) ────────────────
	if res, okRes, handled := dispatchAppOpsTool(c, userID, role, name, args); handled {
		return res, okRes
	}

	// ── LumidOS bridge ────────────────────────────────────────────────────
	// Both legacy app_* and Phase-4 canonical agent_* names land here; the
	// canonical name is normalized to its legacy app_* wire name first, since
	// the schedule server still dispatches on app_*.
	if lumidosToolNames[name] {
		return dispatchLumidosTool(userID, agentToolWireName(name), args)
	}

	log.Printf("[me-agent] unknown tool name=%q user=%s — in prompt catalog but not wired into dispatch", name, userID)
	return map[string]any{"error": "unknown tool: " + name}, false
}

// toolAvailable reports whether `name` is among the tool definitions already
// built for this caller's role. Forcing a tool the caller does not have would
// be a privilege escalation dressed up as a convenience.
func toolAvailable(tools []map[string]any, name string) bool {
	for _, td := range tools {
		if n, _ := td["name"].(string); n == name {
			return true
		}
	}
	return false
}
