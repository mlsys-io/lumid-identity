package handler

import "testing"

// An app installed from someone else must resolve to its AUTHOR's sub, not the
// caller's. Getting this wrong 404s every surface and tool for an app that
// /me/apps reports "ready" — and is invisible to any test run as the author,
// which is exactly how it shipped.
func TestOwnerFromIntentPayload(t *testing.T) {
	for _, tc := range []struct {
		name, payload, app, want string
		ok                       bool
	}{
		{name: "installed from another author",
			payload: `{"slug":"author-sub/mbb-consultant"}`, app: "mbb-consultant",
			want: "author-sub", ok: true},
		{name: "renamed locally via as",
			payload: `{"slug":"author-sub/mbb-consultant","as":"coach"}`, app: "coach",
			want: "author-sub", ok: true},
		{name: "as rename means the source name no longer matches",
			payload: `{"slug":"author-sub/mbb-consultant","as":"coach"}`, app: "mbb-consultant"},
		{name: "a different app's install must not answer",
			payload: `{"slug":"author-sub/other-app"}`, app: "mbb-consultant"},
		{name: "bare slug carries no owner",
			payload: `{"slug":"mbb-consultant"}`, app: "mbb-consultant"},
		{name: "empty owner is not an owner",
			payload: `{"slug":"/mbb-consultant"}`, app: "mbb-consultant"},
		{name: "malformed payload", payload: `not json`, app: "mbb-consultant"},
		{name: "empty payload", payload: ``, app: "mbb-consultant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ownerFromIntentPayload(tc.payload, tc.app)
			if ok != tc.ok || got != tc.want {
				t.Errorf("ownerFromIntentPayload(%q, %q) = (%q, %v), want (%q, %v)",
					tc.payload, tc.app, got, ok, tc.want, tc.ok)
			}
		})
	}
}
