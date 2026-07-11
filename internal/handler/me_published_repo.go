package handler

// Generic read-only helpers over the caller's PUBLISHED xp.io repo — the
// cross-node fallback source when the app bundle lives on the scheduler PVC
// (UKS: identity ≠ scheduler node, the known tenant-app-files gap). All
// requests carry a short-lived user JWT so PRIVATE repos resolve. Best-effort:
// nil on any miss — callers degrade gracefully.
//
// Owner is assumed to be the caller (the common case: a user reads their own
// installed/published app) — the same assumption fetchRepoSpecYAML makes.

import (
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
)

// publishedTreeBlobs lists the blob (file) names directly under <rel> in the
// caller's published repo. Directory entries are skipped; names are sorted.
func publishedTreeBlobs(userID, app, rel string) []string {
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		return nil
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + userID + "/" + app + "/tree/main/" + rel
	code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
	if err != nil || code >= 300 || resp == nil {
		return nil
	}
	entries, _ := resp["entries"].([]any)
	out := []string{}
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		if e == nil {
			continue
		}
		if t, _ := e["type"].(string); t != "" && t != "blob" {
			continue
		}
		name, _ := e["name"].(string)
		if name == "" {
			if p, _ := e["path"].(string); p != "" {
				name = p[strings.LastIndex(p, "/")+1:]
			}
		}
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// publishedRepoBlob reads one file's bytes from the caller's published repo.
// <rel> is the repo-relative path (e.g. "prompts/analyst_system.md").
func publishedRepoBlob(userID, app, rel string) []byte {
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		return nil
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + userID + "/" + app + "/blob/main/" + rel
	code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
	if err != nil || code >= 300 || resp == nil {
		return nil
	}
	content, _ := resp["content"].(string)
	if content == "" {
		return nil
	}
	if dec, derr := base64.StdEncoding.DecodeString(content); derr == nil && len(dec) > 0 {
		return dec
	}
	return []byte(content)
}
