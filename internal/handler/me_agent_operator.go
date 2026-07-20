package handler

// Operator tools for the me-agent chatbox — surface the ops-agent
// healthcheck/remediate surface conversationally to a super_admin operator.
//
// They call the ops-agent container (POST /operate) server-to-server with a
// short-lived, super_admin-scoped bridge JWT (aud=opsagent). operator_healthcheck
// is read-only (dry_run always true, NOT in destructiveTools); operator_remediate
// mutates state and is gated by me_tool_approvals via the destructiveTools
// registry. Both are advertised ONLY to super_admin (buildToolDefsForRole) and
// re-checked at dispatch (defense in depth), and both are audited via writeAudit.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

func opsAgentURL() string {
	if u := strings.TrimSpace(os.Getenv("OPSAGENT_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://opsagent.lumid.svc.cluster.local:8099"
}

// operatorScopes — what the ops-agent /operate surface requires. A dedicated
// non-wildcard scope keeps the bearer least-privilege; the ops-agent gates
// /operate on it plus the super_admin role claim.
var operatorScopes = []string{"opsagent:operate"}

// opsAgentDo issues an authenticated /operate request to the ops-agent as the
// calling super_admin, using a minted bridge JWT (aud=opsagent). Returns
// (parsed body map, status, err).
func opsAgentDo(userID, role string, body map[string]any) (map[string]any, int, error) {
	bearer, _, _, err := common.IssueBridgeJWT(userID, userEmail(userID), role, "opsagent", operatorScopes, 10*time.Minute)
	if err != nil {
		return nil, 0, fmt.Errorf("mint opsagent bearer: %w", err)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, opsAgentURL()+"/operate", bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ops-agent unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out == nil {
		out = map[string]any{"raw": truncateStr(string(rb), 500)}
	}
	return out, resp.StatusCode, nil
}

// operatorToolDefs returns the super_admin-only operator tool definitions.
// Appended in buildToolDefsForRole only when the caller is super_admin, so the
// model never sees them otherwise.
func operatorToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name": "operator_healthcheck",
			"description": "Run a read-only whole-stack health check via the ops-agent (super_admin only). " +
				"Returns a scorecard of the stack's health dimensions. Optionally scope to a single " +
				"dimension. Non-destructive — always runs dry.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dimension": map[string]any{"type": "string", "description": "optional: scope the check to one dimension (e.g. venue_health, disk, dispatch); omit for the full scorecard"},
				},
			},
		},
		{
			"name": "operator_remediate",
			"description": "Run a remediation action for a stack dimension via the ops-agent (super_admin only). " +
				"DESTRUCTIVE — mutates live stack state; requires approval. Set dry_run=true to preview the " +
				"planned actions without applying them. Returns actions_taken + surfaced findings.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dimension": map[string]any{"type": "string", "description": "which stack dimension to remediate (e.g. venue_health, disk, dispatch)"},
					"dry_run":   map[string]any{"type": "boolean", "description": "preview planned actions without applying them (default false)"},
				},
				"required": []string{"dimension"},
			},
		},
	}
}

// toolOperatorHealthcheck dispatches a read-only healthcheck to the ops-agent.
// super_admin-gated; audited. dry_run is forced true (health is read-only).
func toolOperatorHealthcheck(c *gin.Context, userID, role, dimension string) (map[string]any, bool) {
	if role != "super_admin" {
		return map[string]any{"error": "operator_healthcheck requires super_admin"}, false
	}
	body := map[string]any{"action": "healthcheck", "dry_run": true}
	if dimension = strings.TrimSpace(dimension); dimension != "" {
		body["dimension"] = dimension
	}
	out, status, err := opsAgentDo(userID, role, body)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	writeAudit(c, userID, userID, "operator:healthcheck", fmt.Sprintf("dimension=%s (via chatbox)", dimension))
	if status >= 400 {
		return map[string]any{"error": fmt.Sprintf("ops-agent healthcheck: HTTP %d", status), "body": out}, false
	}
	return map[string]any{"dimension": dimension, "scorecard": out}, true
}

// toolOperatorRemediate dispatches a remediation action to the ops-agent.
// super_admin-gated + in destructiveTools (approval-gated); audited.
func toolOperatorRemediate(c *gin.Context, userID, role, dimension string, dryRun bool) (map[string]any, bool) {
	if role != "super_admin" {
		return map[string]any{"error": "operator_remediate requires super_admin"}, false
	}
	if dimension = strings.TrimSpace(dimension); dimension == "" {
		return map[string]any{"error": "dimension is required"}, false
	}
	body := map[string]any{"action": "remediate", "dimension": dimension, "dry_run": dryRun}
	out, status, err := opsAgentDo(userID, role, body)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	writeAudit(c, userID, userID, "operator:remediate", fmt.Sprintf("dimension=%s dry_run=%t (via chatbox)", dimension, dryRun))
	if status >= 400 {
		return map[string]any{"error": fmt.Sprintf("ops-agent remediate: HTTP %d", status), "body": out}, false
	}
	res := map[string]any{"dimension": dimension, "dry_run": dryRun}
	if v, ok := out["actions_taken"]; ok {
		res["actions_taken"] = v
	}
	if v, ok := out["surfaced"]; ok {
		res["surfaced"] = v
	}
	// Fall back to the full body if the ops-agent used a different shape, so
	// nothing is silently dropped from the chat result.
	if _, ok := res["actions_taken"]; !ok {
		if _, ok := res["surfaced"]; !ok {
			res["result"] = out
		}
	}
	return res, true
}
