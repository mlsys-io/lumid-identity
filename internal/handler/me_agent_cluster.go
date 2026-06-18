package handler

// Cluster control-plane tools for the me-agent chatbox — close the
// admin.clusters / admin.worker_ops parity gaps. They call the lumid-cluster
// service (:9910) server-to-server with a short-lived bridge JWT
// (aud=cluster); lumid-cluster's RequireAdmin accepts a JWT whose role claim
// is admin/super_admin. Admin-gated at dispatch (defense in depth).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lumid_identity/internal/common"
)

func clusterBaseURL() string {
	if u := os.Getenv("LUMID_CLUSTER_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://host.docker.internal:9910"
}

// clusterDo issues an admin request to lumid-cluster as the calling admin,
// using a minted bridge JWT (the caller's real role decides whether the
// cluster gate passes). Returns (body, status, err).
func clusterDo(userID, role, method, path string, body any) ([]byte, int, error) {
	bearer, _, _, err := common.IssueBridgeJWT(userID, userEmail(userID), role, "cluster", []string{"cluster:admin"}, 10*time.Minute)
	if err != nil {
		return nil, 0, fmt.Errorf("mint cluster bearer: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, clusterBaseURL()+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("lumid-cluster unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return rb, resp.StatusCode, nil
}

func clusterToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name": "admin_clusters",
			"description": "List GPU clusters / nodes / workers (admin only). kind=clusters|nodes|workers. " +
				"Optional cluster_id / node_id / status filters. Read-only.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind":       map[string]any{"type": "string", "enum": []string{"clusters", "nodes", "workers"}, "description": "what to list (default clusters)"},
					"cluster_id": map[string]any{"type": "string"},
					"node_id":    map[string]any{"type": "string"},
					"status":     map[string]any{"type": "string"},
				},
			},
		},
		{
			"name": "admin_set_worker_pricing",
			"description": "Set a cluster worker's pricing (admin only): cost_per_hour (paid to GPU owner) " +
				"and/or selling_price_per_hour (charged). Audited on the cluster service.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"worker_id":              map[string]any{"type": "string"},
					"cost_per_hour":          map[string]any{"type": "number"},
					"selling_price_per_hour": map[string]any{"type": "number"},
				},
				"required": []string{"worker_id"},
			},
		},
	}
}

func toolAdminClusters(userID, role string, args map[string]any) (map[string]any, bool) {
	if !isAdminRole(role) {
		return map[string]any{"error": "this action requires admin or super_admin"}, false
	}
	kind := strings.ToLower(strings.TrimSpace(toStr(args["kind"])))
	if kind == "" {
		kind = "clusters"
	}
	q := url.Values{}
	if v := toStr(args["cluster_id"]); v != "" {
		q.Set("cluster_id", v)
	}
	if v := toStr(args["node_id"]); v != "" {
		q.Set("node_id", v)
	}
	if v := toStr(args["status"]); v != "" {
		q.Set("status", v)
	}
	var path string
	switch kind {
	case "clusters":
		path = "/api/v1/cluster/clusters"
	case "nodes":
		path = "/api/v1/cluster/nodes"
	case "workers":
		path = "/api/v1/cluster/workers"
	default:
		return map[string]any{"error": "kind must be clusters|nodes|workers"}, false
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	rb, status, err := clusterDo(userID, role, http.MethodGet, path, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 400 {
		return map[string]any{"error": fmt.Sprintf("cluster %s: HTTP %d", kind, status), "body": string(rb)}, false
	}
	var env map[string]any
	_ = json.Unmarshal(rb, &env)
	if data, ok := env["data"]; ok {
		return map[string]any{"kind": kind, "data": data}, true
	}
	return map[string]any{"kind": kind, "raw": string(rb)}, true
}

func toolAdminSetWorkerPricing(userID, role string, args map[string]any) (map[string]any, bool) {
	if !isAdminRole(role) {
		return map[string]any{"error": "this action requires admin or super_admin"}, false
	}
	wid := strings.TrimSpace(toStr(args["worker_id"]))
	if wid == "" {
		return map[string]any{"error": "worker_id required"}, false
	}
	payload := map[string]any{}
	if v, ok := args["cost_per_hour"].(float64); ok {
		payload["cost_per_hour"] = v
	}
	if v, ok := args["selling_price_per_hour"].(float64); ok {
		payload["selling_price_per_hour"] = v
	}
	if len(payload) == 0 {
		return map[string]any{"error": "provide cost_per_hour and/or selling_price_per_hour"}, false
	}
	rb, status, err := clusterDo(userID, role, http.MethodPatch, "/api/v1/cluster/workers/"+wid, payload)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 400 {
		return map[string]any{"error": fmt.Sprintf("patch worker: HTTP %d", status), "body": string(rb)}, false
	}
	var env map[string]any
	_ = json.Unmarshal(rb, &env)
	return map[string]any{"updated": true, "worker_id": wid, "data": env["data"]}, true
}
