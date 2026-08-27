package handler

import "testing"

// The bare-slug rescue in materialiseTenantApp hangs entirely off this rule,
// so it is tested directly. The failure that matters is not "no match" — that
// degrades to the same 404 as before — but "wrong match", which would serve a
// stranger's bundle under a name the user trusts.
func repo(name, sub, vis string) map[string]any {
	return map[string]any{"name": name, "owner_sub": sub, "visibility": vis}
}

func TestUniquePublicOwner(t *testing.T) {
	cases := []struct {
		name  string
		repos []any
		app   string
		want  string
	}{
		{
			name:  "single public match resolves",
			repos: []any{repo("mbb-consultant", "db86775d", "public")},
			app:   "mbb-consultant",
			want:  "db86775d",
		},
		{
			// The real shape on this host: two owners publish "mbb-ai". Picking
			// either would be a silent cross-owner install.
			name:  "two owners of the same name is ambiguous, not a coin flip",
			repos: []any{repo("mbb-ai", "4e06a034", "public"), repo("mbb-ai", "a3f48236", "public")},
			app:   "mbb-ai",
			want:  "",
		},
		{
			name:  "private repos never match",
			repos: []any{repo("auto-quant", "70f192ce", "private")},
			app:   "auto-quant",
			want:  "",
		},
		{
			// A search for "mbb" returns near-misses; only an exact name counts.
			name:  "substring hits are not matches",
			repos: []any{repo("mbb-casebook-cases", "db86775d", "public"), repo("mbb-ai", "a3f48236", "public")},
			app:   "mbb",
			want:  "",
		},
		{
			name:  "one public among several private resolves",
			repos: []any{repo("x", "priv1", "private"), repo("x", "pub1", "public"), repo("x", "priv2", "private")},
			app:   "x",
			want:  "pub1",
		},
		{
			name:  "a match with no owner_sub is unusable",
			repos: []any{repo("x", "", "public")},
			app:   "x",
			want:  "",
		},
		{
			name:  "empty search result",
			repos: []any{},
			app:   "nothing",
			want:  "",
		},
		{
			name:  "malformed rows are skipped, not fatal",
			repos: []any{"not-an-object", nil, repo("x", "pub1", "public")},
			app:   "x",
			want:  "pub1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := uniquePublicOwner(tc.repos, tc.app); got != tc.want {
				t.Fatalf("uniquePublicOwner(%q) = %q, want %q", tc.app, got, tc.want)
			}
		})
	}
}
