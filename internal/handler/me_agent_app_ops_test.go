package handler

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeAppJoin pins the surface-path jail: bundle-relative paths join cleanly
// under appDir; anything that could escape (empty, traversal, absolute, NUL,
// clean-to-parent) is rejected. This is the guard that keeps an attacker-
// supplied surface path inside the app bundle.
func TestSafeAppJoin(t *testing.T) {
	appDir := t.TempDir()

	valid := []struct {
		name string
		rel  string
	}{
		{"ui-home-md", "ui/home.md"},
		{"dotui-page-yaml", ".ui/page.yaml"},
	}
	for _, c := range valid {
		t.Run("ok/"+c.name, func(t *testing.T) {
			got, err := safeAppJoin(appDir, c.rel)
			if err != nil {
				t.Fatalf("safeAppJoin(%q, %q) unexpected error: %v", appDir, c.rel, err)
			}
			if got != filepath.Join(appDir, c.rel) {
				t.Errorf("safeAppJoin(%q, %q) = %q, want %q", appDir, c.rel, got, filepath.Join(appDir, c.rel))
			}
			if got != appDir && !strings.HasPrefix(got, appDir+string(filepath.Separator)) {
				t.Errorf("safeAppJoin result %q is not under appDir %q", got, appDir)
			}
		})
	}

	reject := []struct {
		name string
		rel  string
	}{
		{"empty", ""},
		{"parent-escape", "../escape"},
		{"deep-escape", "../../etc/passwd"},
		{"absolute", "/etc/passwd"},
		{"nul-byte", "a\x00b"},
		{"clean-to-parent", "ui/../../x"},
	}
	for _, c := range reject {
		t.Run("reject/"+c.name, func(t *testing.T) {
			got, err := safeAppJoin(appDir, c.rel)
			if err == nil {
				t.Errorf("safeAppJoin(%q, %q) = %q, nil — want an error (path must be rejected)", appDir, c.rel, got)
			}
		})
	}
}

// TestResolveSurfacePaths covers the surface-name → (markdown | page-spec)
// resolution. Exactly one of mdPath/pagePath is set on success; .yaml/.yml
// entries resolve to the page slot, everything else to the markdown slot;
// "home" falls back to the legacy Surface block; unknown names → ok=false.
func TestResolveSurfacePaths(t *testing.T) {
	cases := []struct {
		name        string
		ui          *appUI
		surface     string
		wantMD      string
		wantPage    string
		wantOK      bool
	}{
		{
			name:     "home-surface-markdown",
			ui:       &appUI{Surface: &appUISurface{Markdown: "ui/home.md"}},
			surface:  "home",
			wantMD:   "ui/home.md",
			wantPage: "",
			wantOK:   true,
		},
		{
			name:     "home-surface-page",
			ui:       &appUI{Surface: &appUISurface{Page: "ui/page.yaml"}},
			surface:  "home",
			wantMD:   "",
			wantPage: "ui/page.yaml",
			wantOK:   true,
		},
		{
			name:     "named-surface-md",
			ui:       &appUI{Surfaces: map[string]string{"comp": "ui/comp.md"}},
			surface:  "comp",
			wantMD:   "ui/comp.md",
			wantPage: "",
			wantOK:   true,
		},
		{
			name:     "named-surface-yaml-is-page",
			ui:       &appUI{Surfaces: map[string]string{"comp": "ui/comp.yaml"}},
			surface:  "comp",
			wantMD:   "",
			wantPage: "ui/comp.yaml",
			wantOK:   true,
		},
		{
			name:     "missing-surface",
			ui:       &appUI{Surface: &appUISurface{Markdown: "ui/home.md"}},
			surface:  "missing",
			wantMD:   "",
			wantPage: "",
			wantOK:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			md, page, ok := resolveSurfacePaths(c.ui, c.surface)
			if ok != c.wantOK {
				t.Fatalf("resolveSurfacePaths(%s) ok = %v, want %v", c.name, ok, c.wantOK)
			}
			if md != c.wantMD {
				t.Errorf("resolveSurfacePaths(%s) mdPath = %q, want %q", c.name, md, c.wantMD)
			}
			if page != c.wantPage {
				t.Errorf("resolveSurfacePaths(%s) pagePath = %q, want %q", c.name, page, c.wantPage)
			}
		})
	}
}

// TestResolveSurfacePathsExclusive guards the documented invariant: on success
// exactly one of mdPath/pagePath is non-empty (never both, never neither).
func TestResolveSurfacePathsExclusive(t *testing.T) {
	uis := []*appUI{
		{Surface: &appUISurface{Markdown: "ui/home.md"}},
		{Surface: &appUISurface{Page: "ui/page.yaml"}},
		{Surfaces: map[string]string{"home": "ui/home.md"}},
		{Surfaces: map[string]string{"home": "ui/home.yaml"}},
	}
	for i, ui := range uis {
		md, page, ok := resolveSurfacePaths(ui, "home")
		if !ok {
			t.Fatalf("case %d: expected ok=true", i)
		}
		if (md == "") == (page == "") {
			t.Errorf("case %d: exactly one of mdPath/pagePath must be set; got md=%q page=%q", i, md, page)
		}
	}
}

// TestValidAppSlug checks the app-name allowlist that gates resolveAppDir's
// filepath.Join — it must accept normal slugs and reject anything that could
// traverse out of the tenant apps dir.
func TestValidAppSlug(t *testing.T) {
	valid := []string{"auto-quant", "mbb-ai", "a", "App_1.0", "lumid-gpu-rentals"}
	for _, s := range valid {
		if !validAppSlug(s) {
			t.Errorf("validAppSlug(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "..", "../x", "a/b", "a\x00b", ".hidden", "-leading"}
	for _, s := range invalid {
		if validAppSlug(s) {
			t.Errorf("validAppSlug(%q) = true, want false", s)
		}
	}
}
