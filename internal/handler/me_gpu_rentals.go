package handler

// GPU rentals — server-side store + FlowMesh integration. Replaces the old
// client-side localStorage so a generated page (lumid:table over
// me://gpu-rentals + a lumid:form bound to gpu_rental.create) can be fully
// live, with no native component.
//
//   GET  /me/gpu-rentals            → list the caller's rentals (read source)
//   form-action gpu_rental.create   → build SSH task YAML, submit to FlowMesh
//   form-action gpu_rental.cancel   → cancel the rental's workflow
//
// FlowMesh is reached server-side at FLOWMESH_BASE_URL (default the cloud Host
// kv.run:8000/flowmesh) with a freshly-minted, short-lived flowmesh bearer.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func init() {
	// Register the GPU-rental form actions on the allowlist (me_form_action.go).
	formActions["gpu_rental.create"] = gpuRentalCreateAction
	formActions["gpu_rental.cancel"] = gpuRentalCancelAction
}

func flowmeshBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("FLOWMESH_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://kv.run:8000/flowmesh"
}

// MeGpuRentalsList — GET /me/gpu-rentals. Backs the me://gpu-rentals source.
func MeGpuRentalsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var rows []models.GpuRental
	common.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&rows)

	// Fetch live status dynamically from FlowMesh for still-active rentals
	// (the store is just the per-user index; FlowMesh is the source of truth
	// for status). Best-effort + bounded so a slow/unreachable Host doesn't
	// stall the list — we fall back to the stored status.
	email, role := userEmailRole(userID)
	refreshed := 0
	for i := range rows {
		s := rows[i].Status
		if rows[i].TaskID == "" || s == "done" || s == "cancelled" || s == "error" || refreshed >= 15 {
			continue
		}
		if live := flowmeshTaskStatus(userID, email, role, rows[i].TaskID); live != "" && live != s {
			rows[i].Status = live
			common.DB.Model(&rows[i]).Update("status", live)
		}
		refreshed++
	}

	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		out = append(out, gin.H{
			"id": r.ID, "name": r.Name, "task_id": r.TaskID, "workflow_id": r.WorkflowID,
			"gpu": r.GPU, "gpu_memory_gb": r.GPUMemoryGB, "cpu": r.CPU, "memory_gb": r.MemoryGB,
			"mode": r.Mode, "ttl_seconds": r.TTLSeconds, "status": r.Status,
			"created": r.CreatedAt.Format(time.RFC3339),
		})
	}
	ok_(c, "ok", gin.H{"rentals": out, "count": len(out)})
}

// ── form value coercion (lumid:form sends inputs as strings) ──────────────────

func valStr(v map[string]any, k string) string {
	if s, ok := v[k].(string); ok {
		return strings.TrimSpace(s)
	}
	if v[k] != nil {
		return strings.TrimSpace(fmt.Sprintf("%v", v[k]))
	}
	return ""
}

func valInt(v map[string]any, k string, def int) int {
	s := valStr(v, k)
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int(f)
	}
	return def
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func yq(s string) string {
	return strconv.Quote(s)
}

// buildSshTaskYAML mirrors the frontend buildSshTaskYaml (flowmesh.ts).
func buildSshTaskYAML(name, user, mode, image string, ttl, idle, gpu, gpuMemGB, cpu, memGB int, pubKey string, env map[string]string) string {
	if user == "" {
		user = "flowmesh"
	}
	if mode == "" {
		mode = "proxy"
	}
	ttl = clampInt(ttl, 60, 28800)
	idle = clampInt(idle, 60, 28800)
	gpu = clampInt(gpu, 0, 64)
	cpu = clampInt(cpu, 0, 256)
	var b strings.Builder
	b.WriteString("apiVersion: flowmesh/v1\n")
	b.WriteString("kind: SSHTask\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: " + yq(name) + "\n")
	b.WriteString("spec:\n")
	b.WriteString("  taskType: ssh\n")
	b.WriteString("  interactive: true\n")
	b.WriteString("  user: " + yq(user) + "\n")
	b.WriteString("  accessMode: " + mode + "\n")
	b.WriteString("  ttlSeconds: " + strconv.Itoa(ttl) + "\n")
	b.WriteString("  idleTimeoutSeconds: " + strconv.Itoa(idle) + "\n")
	b.WriteString("  authorizedKeys:\n")
	b.WriteString("    - " + yq(strings.TrimSpace(pubKey)) + "\n")
	if image != "" {
		b.WriteString("  image: " + yq(image) + "\n")
	}
	if len(env) > 0 {
		b.WriteString("  env:\n")
		for k, v := range env {
			b.WriteString("    " + k + ": " + yq(v) + "\n")
		}
	}
	if gpu > 0 || cpu > 0 || memGB > 0 || gpuMemGB > 0 {
		b.WriteString("  resources:\n    hardware:\n")
		if cpu > 0 {
			b.WriteString("      cpu: " + strconv.Itoa(cpu) + "\n")
		}
		if memGB > 0 {
			b.WriteString("      memory: \"" + strconv.Itoa(memGB) + "Gi\"\n")
		}
		if gpu > 0 {
			b.WriteString("      gpu:\n        count: " + strconv.Itoa(gpu) + "\n")
			if gpuMemGB > 0 {
				b.WriteString("        memory: \"" + strconv.Itoa(gpuMemGB) + "GB\"\n")
			}
		}
	}
	return b.String()
}

// flowmeshDo issues an authenticated request to the FlowMesh Host. body may be
// nil. Returns the response bytes + status.
func flowmeshDo(userID, email, role, method, path, contentType string, body []byte) ([]byte, int, error) {
	bearer, _, _, err := common.IssueBridgeJWT(userID, email, role, "flowmesh", []string{"flowmesh:ssh"}, 10*time.Minute)
	if err != nil {
		return nil, 0, fmt.Errorf("mint flowmesh bearer: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, flowmeshBaseURL()+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("flowmesh unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return rb, resp.StatusCode, nil
}

// flowmeshTaskStatus fetches a single task's live status from FlowMesh with a
// short timeout. Returns "" on any failure (caller keeps the stored status).
func flowmeshTaskStatus(userID, email, role, taskID string) string {
	bearer, _, _, err := common.IssueBridgeJWT(userID, email, role, "flowmesh", []string{"flowmesh:ssh"}, 10*time.Minute)
	if err != nil {
		return ""
	}
	req, err := http.NewRequest(http.MethodGet, flowmeshBaseURL()+"/api/v1/tasks/"+taskID, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return ""
	}
	rb, _ := io.ReadAll(resp.Body)
	var t struct {
		Status string `json:"status"`
		State  string `json:"state"`
	}
	if json.Unmarshal(rb, &t) != nil {
		return ""
	}
	if t.Status != "" {
		return strings.ToLower(t.Status)
	}
	return strings.ToLower(t.State)
}

func userEmailRole(userID string) (string, string) {
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err == nil {
		return u.Email, u.Role
	}
	return "", "user"
}

// gpuRentalCreateAction — allowlisted: builds the SSH task + submits to FlowMesh.
func gpuRentalCreateAction(_ *gin.Context, userID, _ string, values map[string]any) (any, error) {
	name := valStr(values, "name")
	if name == "" {
		return nil, fmt.Errorf("rental name is required")
	}
	pubKey := valStr(values, "ssh_public_key")
	if !strings.HasPrefix(pubKey, "ssh-") {
		return nil, fmt.Errorf("a valid SSH public key is required")
	}
	// Resolve image preset.
	image := ""
	switch valStr(values, "image") {
	case "Custom":
		image = valStr(values, "custom_image")
	case "CPU-only Python":
		image = "python:3.11-slim"
	default: // "FlowMesh SSH (default)" or empty → Host default image
		image = ""
	}
	// Parse env (KEY=VALUE per line).
	env := map[string]string{}
	for _, line := range strings.Split(valStr(values, "env"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if eq := strings.Index(line, "="); eq > 0 {
			env[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
		}
	}
	gpu := valInt(values, "gpu", 1)
	gpuMem := valInt(values, "gpu_memory_gb", 16)
	cpu := valInt(values, "cpu", 2)
	memGB := valInt(values, "memory_gb", 8)
	ttlMin := valInt(values, "ttl_minutes", 60)
	idleMin := valInt(values, "idle_minutes", 15)
	mode := valStr(values, "access_mode")
	if mode == "" {
		mode = "proxy"
	}

	yaml := buildSshTaskYAML(name, "flowmesh", mode, image, ttlMin*60, idleMin*60, gpu, gpuMem, cpu, memGB, pubKey, env)

	email, role := userEmailRole(userID)
	rb, status, err := flowmeshDo(userID, email, role, http.MethodPost, "/api/v1/workflows", "text/plain", []byte(yaml))
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("flowmesh %d: %s", status, truncateStr(string(rb), 200))
	}
	var sr struct {
		WorkflowID string `json:"workflow_id"`
		Tasks      []struct {
			TaskID string `json:"task_id"`
		} `json:"tasks"`
	}
	_ = json.Unmarshal(rb, &sr)
	taskID := ""
	if len(sr.Tasks) > 0 {
		taskID = sr.Tasks[0].TaskID
	}

	rental := models.GpuRental{
		ID: uuid.NewString(), UserID: userID, Name: name,
		TaskID: taskID, WorkflowID: sr.WorkflowID,
		GPU: gpu, GPUMemoryGB: gpuMem, CPU: cpu, MemoryGB: memGB,
		Mode: mode, TTLSeconds: ttlMin * 60, Status: "submitted",
	}
	if err := common.DB.Create(&rental).Error; err != nil {
		// The rental WAS submitted to FlowMesh; surface that even if our
		// local record failed to persist.
		return gin.H{"ok": true, "task_id": taskID, "workflow_id": sr.WorkflowID, "warning": "submitted but not recorded locally"}, nil
	}
	return gin.H{"ok": true, "id": rental.ID, "task_id": taskID, "workflow_id": sr.WorkflowID}, nil
}

// gpuRentalCancelAction — allowlisted: cancels a rental's FlowMesh workflow.
func gpuRentalCancelAction(_ *gin.Context, userID, _ string, values map[string]any) (any, error) {
	id := valStr(values, "id")
	wf := valStr(values, "workflow_id")
	var rental models.GpuRental
	if id != "" {
		if err := common.DB.Where("id = ? AND user_id = ?", id, userID).First(&rental).Error; err == nil {
			wf = rental.WorkflowID
		}
	}
	if wf == "" {
		return nil, fmt.Errorf("workflow_id (or a known rental id) required")
	}
	email, role := userEmailRole(userID)
	rb, status, err := flowmeshDo(userID, email, role, http.MethodPost, "/api/v1/workflows/"+wf+"/cancel", "", nil)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("flowmesh %d: %s", status, truncateStr(string(rb), 200))
	}
	if rental.ID != "" {
		common.DB.Model(&rental).Update("status", "cancelled")
	}
	return gin.H{"ok": true, "workflow_id": wf, "status": "cancelled"}, nil
}
