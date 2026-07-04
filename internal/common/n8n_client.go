// n8n REST client.
//
// Used by /me/workflows + /me/runs aggregators to surface n8n-authored
// workflows alongside scheduled xpio loops in one unified list.
//
// Surface intentionally narrow: list workflows, list executions, get
// single execution. Auth is per-request: the caller supplies a cookie
// (n8n's session) or bridge JWT once the W2 SSO bridge lands. For W1
// the aggregator tolerates a 401 from n8n (no session yet) and returns
// an empty slice — the user sees only scheduled workflows until they
// hop into the iframe to log in.

package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// N8nClient wraps the upstream n8n REST API.
type N8nClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewN8nClient — base URL defaults to the in-cluster service. The
// scheduler + identity reach n8n via the lum.id-side nginx proxy,
// which strips the /n8n/ prefix; the upstream service speaks at
// http://172.17.0.1:5678 by default. Override via N8N_BASE_URL.
func NewN8nClient() *N8nClient {
	base := os.Getenv("N8N_BASE_URL")
	if base == "" {
		base = "http://172.17.0.1:5678"
	}
	return &N8nClient{
		BaseURL: strings.TrimRight(base, "/"),
		HTTP: &http.Client{
			Timeout: 8 * time.Second,
		},
	}
}

// N8nWorkflow is the slim shape we read from /rest/workflows.
// n8n returns far more fields; we keep only what the aggregator needs.
type N8nWorkflow struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Active    bool             `json:"active"`
	CreatedAt string           `json:"createdAt"`
	UpdatedAt string           `json:"updatedAt"`
	Tags      []map[string]any `json:"tags,omitempty"`
	Settings  map[string]any   `json:"settings,omitempty"`
	Nodes     []N8nNode        `json:"nodes,omitempty"`
}

// N8nNode — just enough to count steps + render the DAG label.
type N8nNode struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Position   []float64      `json:"position,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// N8nExecution is the slim shape we read from /rest/executions.
type N8nExecution struct {
	ID             string `json:"id"`
	WorkflowID     string `json:"workflowId"`
	Status         string `json:"status"`         // "success" | "error" | "running" | "waiting" | "canceled"
	Mode           string `json:"mode,omitempty"` // "manual" | "trigger" | "webhook" | ...
	StartedAt      string `json:"startedAt"`
	StoppedAt      string `json:"stoppedAt,omitempty"`
	Finished       bool   `json:"finished"`
	RetryOf        string `json:"retryOf,omitempty"`
	RetrySuccessID string `json:"retrySuccessId,omitempty"`
}

// listWorkflowsResp matches n8n's paginated wrapper.
type listWorkflowsResp struct {
	Data []N8nWorkflow `json:"data"`
}

type listExecutionsResp struct {
	Data       []N8nExecution `json:"data"`
	NextCursor string         `json:"nextCursor,omitempty"`
}

// ErrUnauthenticated is returned when n8n responds 401 — typically
// the caller hasn't established an n8n session yet. Aggregators should
// log + continue (return empty slice) rather than fail the whole
// /me/workflows response.
var ErrUnauthenticated = errors.New("n8n: not authenticated")

// ListWorkflows returns active + inactive workflows visible to the
// supplied session. Cookie value is the caller's n8n session cookie
// (W1: best-effort, often empty; W2: minted via SSO bridge).
func (c *N8nClient) ListWorkflows(ctx context.Context, sessionCookie string) ([]N8nWorkflow, error) {
	var resp listWorkflowsResp
	if err := c.do(ctx, "GET", "/rest/workflows", sessionCookie, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetWorkflow fetches a single workflow definition (used by the
// workflow-detail page and the n8n→YAML translator in W2).
func (c *N8nClient) GetWorkflow(ctx context.Context, id, sessionCookie string) (*N8nWorkflow, error) {
	var resp struct {
		Data N8nWorkflow `json:"data"`
	}
	if err := c.do(ctx, "GET", "/rest/workflows/"+id, sessionCookie, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListExecutions returns recent runs. `workflowID` filters; pass
// empty string for all. Limit defaults to 100 in n8n.
func (c *N8nClient) ListExecutions(ctx context.Context, workflowID, status, sessionCookie string) ([]N8nExecution, error) {
	q := []string{}
	if workflowID != "" {
		q = append(q, "filter="+urlEscape(fmt.Sprintf(`{"workflowId":"%s"}`, workflowID)))
	}
	if status != "" {
		// n8n's filter encoding is JSON; combine if both present.
		// Simplify: append a separate status query param if only status set.
		if workflowID == "" {
			q = append(q, "filter="+urlEscape(fmt.Sprintf(`{"status":"%s"}`, status)))
		}
	}
	path := "/rest/executions"
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	var resp listExecutionsResp
	if err := c.do(ctx, "GET", path, sessionCookie, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetExecution returns a single run with per-node state when n8n
// provides it (`?includeData=true`).
func (c *N8nClient) GetExecution(ctx context.Context, id, sessionCookie string) (*N8nExecution, error) {
	var resp struct {
		Data N8nExecution `json:"data"`
	}
	if err := c.do(ctx, "GET", "/rest/executions/"+id, sessionCookie, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// do — shared request driver. Adds Cookie header when supplied;
// surfaces 401 as ErrUnauthenticated so aggregators can soft-fail.
func (c *N8nClient) do(ctx context.Context, method, path, sessionCookie string, out any) error {
	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}
	if sessionCookie != "" {
		req.Header.Set("Cookie", "n8n-auth="+sessionCookie)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "lumid-identity/1.0 n8n-client")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("n8n %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthenticated
	case http.StatusNotFound:
		return fmt.Errorf("n8n %s %s: 404 not found", method, path)
	default:
		return fmt.Errorf("n8n %s %s: status %d", method, path, resp.StatusCode)
	}
}

func urlEscape(s string) string {
	// Minimal escape — n8n's filter is a JSON literal we URL-encode by
	// hand. Avoid importing net/url for one call site.
	r := strings.NewReplacer(
		"{", "%7B",
		"}", "%7D",
		"\"", "%22",
		":", "%3A",
		",", "%2C",
		" ", "%20",
	)
	return r.Replace(s)
}
