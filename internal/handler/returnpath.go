package handler

// Shared return-address helpers for OAuth flows.
//
// `return_to` must be validated on the server independently of the SPA —
// the SPA's check is bypassable by a crafted request. We reject anything
// that isn't a same-origin path under a known prefix (open-redirect /
// header-injection defense). The connect-flow `state` carries {sub, r} so
// the post-consent destination survives the Google round-trip.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

var safeReturnPrefixes = []string{"/studio", "/dashboard", "/app", "/account", "/onboarding"}

// isSafeReturnPath reports whether p is a safe same-origin redirect path.
func isSafeReturnPath(p string) bool {
	if p == "/" {
		return true
	}
	if p == "" || strings.HasPrefix(p, "//") || strings.Contains(p, "://") {
		return false
	}
	// Reject a scheme (e.g. "javascript:") appearing before the first slash.
	if i := strings.IndexByte(p, ':'); i >= 0 {
		s := strings.IndexByte(p, '/')
		if s == -1 || i < s {
			return false
		}
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, pre := range safeReturnPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

type connectState struct {
	S string `json:"s"` // user sub
	R string `json:"r"` // validated return_to (may be empty)
}

// encodeConnectState packs the user sub + return_to into the OAuth state.
func encodeConnectState(sub, returnTo string) string {
	b, _ := json.Marshal(connectState{S: sub, R: returnTo})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeConnectState reverses encodeConnectState. A bare (legacy) sub that
// isn't base64-JSON decodes to {sub, ""} so old in-flight grants still work.
func decodeConnectState(raw string) (sub string, returnTo string) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return raw, ""
	}
	var v connectState
	if json.Unmarshal(b, &v) != nil || v.S == "" {
		return raw, ""
	}
	return v.S, v.R
}
