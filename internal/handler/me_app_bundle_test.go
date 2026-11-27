package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppBundlePathOK(t *testing.T) {
	ok := []string{"", "sample_data/ofi_momentum_v1.lqts", "commands/backtest.py", "ui/strategies.yaml", ".xpcloud.yaml", "notes"}
	bad := []string{"../x", "/etc/passwd", ".env", ".user-overrides.yaml", ".git/config", "a/.hidden",
		"secrets/x.yaml", "keys/id_rsa", "conf/api_key.txt", "cert.pem", "data/token.json", "a/../../x"}
	for _, p := range ok {
		if !appBundlePathOK(normAppFileRel(p)) {
			t.Errorf("%q should be readable", p)
		}
	}
	for _, p := range bad {
		if appBundlePathOK(normAppFileRel(p)) {
			t.Errorf("%q must not be readable", p)
		}
	}
}

// A plain user reads their own install or the published bundle — never the
// operator-shared tree, which keeps the operator's runtime state.
func TestAppBundleRootKeepsUsersOutOfTheOperatorTree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	op := filepath.Join(home, ".xp", "apps", "qr")
	if err := os.MkdirAll(op, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := appBundleRoot("admin-sub", "admin", "qr"); got != op {
		t.Errorf("admin should read the operator tree, got %q", got)
	}
	mine := filepath.Join(tenantAppsDir("user-sub"), "qr")
	if err := os.MkdirAll(mine, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := appBundleRoot("user-sub", "user", "qr"); got != mine {
		t.Errorf("a user reads their own install, got %q", got)
	}
	// Without an install a user falls to the PUBLISHED bundle
	// (materialiseTenantApp), never resolveAppDir's operator tree.
	src := uncommentedGo(mustRead(t, "me_app_bundle.go"))
	body := src[strings.Index(src, "func appBundleRoot("):]
	body = body[:strings.Index(body, "\n}\n")]
	if strings.Count(body, "resolveAppDir(") != 1 || !strings.Contains(body, `role == "admin" || role == "super_admin"`) {
		t.Errorf("resolveAppDir (which includes the operator tree) must stay behind the admin check:\n%s", body)
	}
}

func TestAppBundleFileBody(t *testing.T) {
	small := appBundleFileBody("qr", "a.lqts", []byte("strategy x {}"), "bundle")
	if small["content"] != "strategy x {}" || small["truncated"] != false {
		t.Errorf("small file: %+v", small)
	}
	big := appBundleFileBody("qr", "b.txt", []byte(strings.Repeat("é", appBundleMaxBytes)), "bundle")
	if big["truncated"] != true || big["binary"] == true {
		t.Errorf("a cut through a rune must stay text: %+v", big["binary"])
	}
	if s, _ := big["content"].(string); len(s) > appBundleMaxBytes {
		t.Errorf("content over the cap: %d", len(s))
	}
	bin := appBundleFileBody("qr", "c.bin", []byte{0xff, 0xfe, 0x00, 0x81}, "bundle")
	if bin["binary"] != true || bin["content"] != nil {
		t.Errorf("binary must be reported, not returned: %+v", bin)
	}
}
