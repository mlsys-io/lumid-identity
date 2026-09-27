package handler

// Owner edits — prompt cards, .xpcloud.yaml, UI surfaces — failed for every
// cloud-installed app with 403 "operator-shared (read-only)": identity mounts no
// tenant volume, so resolveOwnedAppDir never found the caller's own install and
// concluded the app must be someone else's. They now queue an app_file_write
// for the scheduler (me_app_file_intent.go), and reads overlay the applied
// result. These tests pin the three decisions that can regress independently:
// which writes route where, which overlay a reader sees, and that each handler
// still queues rather than reaching for a disk this pod does not have.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func afwAt(min int) *time.Time {
	t := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
	return &t
}

func afwWrite(id, status string, at *time.Time, payload string) models.MeAppIntent {
	return models.MeAppIntent{ID: id, Action: appFileWriteAction, UserSub: "u1",
		Status: status, Payload: payload, CompletedAt: at}
}

func TestAppFileOverlay_DoneWriteWins_FailedAndPendingIgnored(t *testing.T) {
	writes := []models.MeAppIntent{
		// newest-first, as the query orders them
		afwWrite("pending", "pending", nil, `{"app":"a","path":"prompts/x.md","op":"write","content":"PENDING"}`),
		afwWrite("failed", "failed", afwAt(9), `{"app":"a","path":"prompts/x.md","op":"write","content":"CONFLICTED"}`),
		afwWrite("new", "done", afwAt(5), `{"app":"a","path":"prompts/x.md","op":"write","content":"NEW"}`),
		afwWrite("old", "done", afwAt(1), `{"app":"a","path":"prompts/x.md","op":"write","content":"OLD"}`),
		afwWrite("other", "done", afwAt(6), `{"app":"b","path":"prompts/x.md","op":"write","content":"OTHER APP"}`),
	}
	ov := overlaysFromIntents(writes, nil, "a")
	e, ok := ov["prompts/x.md"]
	if !ok {
		t.Fatal("a done write produced no overlay")
	}
	if string(e.Content) != "NEW" || e.IntentID != "new" {
		t.Fatalf("overlay = %q (%s); want the newest DONE write, not a failed/pending/older/other-app one",
			e.Content, e.IntentID)
	}
	// Order must not matter — the newest completed_at wins even if rows arrive
	// out of order.
	rev := []models.MeAppIntent{writes[3], writes[2]}
	if got := overlaysFromIntents(rev, nil, "a")["prompts/x.md"]; string(got.Content) != "NEW" {
		t.Fatalf("out-of-order rows: got %q, want NEW", got.Content)
	}
}

func TestAppFileOverlay_LaterInstallOrUpdateSupersedes(t *testing.T) {
	writes := []models.MeAppIntent{
		afwWrite("w", "done", afwAt(5), `{"app":"a","path":".xpcloud.yaml","op":"write","content":"name: a"}`),
	}
	cases := []struct {
		name   string
		resets []models.MeAppIntent
		want   bool
	}{
		{"no reset", nil, true},
		{"install before the write", []models.MeAppIntent{
			{Action: "install", Status: "done", Payload: `{"slug":"owner/a"}`, CompletedAt: afwAt(1)}}, true},
		{"install after the write", []models.MeAppIntent{
			{Action: "install", Status: "done", Payload: `{"slug":"owner/a"}`, CompletedAt: afwAt(7)}}, false},
		{"update after the write", []models.MeAppIntent{
			{Action: "update", Status: "done", Payload: `{"app":"a"}`, CompletedAt: afwAt(7)}}, false},
		{"dry-run update after the write", []models.MeAppIntent{
			{Action: "update", Status: "done", Payload: `{"app":"a","dry_run":true}`, CompletedAt: afwAt(7)}}, true},
		{"failed install after the write", []models.MeAppIntent{
			{Action: "install", Status: "failed", Payload: `{"slug":"owner/a"}`, CompletedAt: afwAt(7)}}, true},
		{"another app's install", []models.MeAppIntent{
			{Action: "install", Status: "done", Payload: `{"slug":"owner/b"}`, CompletedAt: afwAt(7)}}, true},
		{"install renamed onto this app", []models.MeAppIntent{
			{Action: "install", Status: "done", Payload: `{"slug":"owner/x","as":"a"}`, CompletedAt: afwAt(7)}}, false},
	}
	for _, c := range cases {
		_, got := overlaysFromIntents(writes, c.resets, "a")[appFileSpecRel]
		if got != c.want {
			t.Errorf("%s: overlay present = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAppFileOverlay_DeleteAndListing(t *testing.T) {
	writes := []models.MeAppIntent{
		afwWrite("d", "done", afwAt(8), `{"app":"a","path":"prompts/judge.md","op":"delete"}`),
		afwWrite("w1", "done", afwAt(6), `{"app":"a","path":"prompts/judge.md","op":"write","content":"J"}`),
		afwWrite("w2", "done", afwAt(5), `{"app":"a","path":"prompts/new_card.md","op":"write","content":"N"}`),
		afwWrite("w3", "done", afwAt(4), `{"app":"a","path":"./.ui/home.md","op":"write","content":"H"}`),
	}
	all := overlaysFromIntents(writes, nil, "a")
	if e := all["prompts/judge.md"]; !e.Deleted {
		t.Fatalf("a delete newer than the write must win: %+v", e)
	}
	if e, ok := all[".ui/home.md"]; !ok || string(e.Content) != "H" {
		t.Fatalf("overlay keys must be normalised (./.ui/home.md → .ui/home.md): %v", all)
	}
	names := overlayNamesUnder(all, "prompts")
	if len(names) != 2 {
		t.Fatalf("prompts/ listing = %v; want judge.md (deleted) + new_card.md (created)", names)
	}
	if !names["judge.md"].Deleted || string(names["new_card.md"].Content) != "N" {
		t.Fatalf("listing entries wrong: %+v", names)
	}
}

func TestAppFileIntentPathAllowlist(t *testing.T) {
	ok := []string{"prompts/analyst_system.md", ".ui/home.md", ".ui/page.yaml", ".ui/x.yml",
		"ui/page.yaml", ".xpcloud.yaml", "./prompts/a.md"}
	bad := []string{"prompts/a b.md", "prompts/sub/a.md", "ui/home.md", "xpcloud.yaml",
		"../prompts/a.md", "prompts/../../x.md", "data/x.json", "/etc/passwd", "prompts/a.txt", ""}
	for _, p := range ok {
		if !appFileIntentPathOK(normAppFileRel(p)) {
			t.Errorf("%q should be writable via the scheduler", p)
		}
	}
	for _, p := range bad {
		if appFileIntentPathOK(normAppFileRel(p)) {
			t.Errorf("%q must be refused before enqueueing — the picker would refuse it", p)
		}
	}
}

// ownerWriteTarget without a DB: an install identity can SEE is direct (the
// on-prem path, unchanged); an operator-shared bundle stays shared/403.
func TestOwnerWriteTarget_DirectAndShared(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	prevDB := common.DB
	common.DB = nil
	t.Cleanup(func() { common.DB = prevDB })

	if err := os.MkdirAll(filepath.Join(home, ".tenants", "u1", ".xp", "apps", "mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".xp", "apps", "theirs"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir, direct, via, shared := ownerWriteTarget("u1", "mine")
	if !direct || via || shared || dir == "" {
		t.Fatalf("own visible install: dir=%q direct=%v via=%v shared=%v; want direct", dir, direct, via, shared)
	}
	dir, direct, via, shared = ownerWriteTarget("u1", "theirs")
	if direct || via || !shared || dir != "" {
		t.Fatalf("operator-shared app: dir=%q direct=%v via=%v shared=%v; want shared only", dir, direct, via, shared)
	}
	if _, d, v, _ := ownerWriteTarget("u1", "../u2/.xp/apps/mine"); d || v {
		t.Fatal("a traversal app name must never be writable")
	}
}

// The UKS case: nothing on this disk, but the caller installed the app — the
// write is queued, not refused. And the overlay round-trips through the DB.
func TestOwnerWriteTarget_ViaIntentAndOverlayDB(t *testing.T) {
	db := setupIntentDB(t)
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	now := time.Now()
	past := now.Add(-time.Hour)
	rows := []models.MeAppIntent{
		{ID: "afw-install", Action: "install", UserSub: "u-afw", Status: "done",
			Payload: `{"slug":"owner/cloudapp"}`, CreatedAt: past, CompletedAt: &past},
		{ID: "afw-write", Action: appFileWriteAction, UserSub: "u-afw", Status: "done",
			Payload:   `{"app":"cloudapp","path":"prompts/p.md","op":"write","content":"EDITED","base_sha":""}`,
			CreatedAt: now, CompletedAt: &now},
		{ID: "afw-failed", Action: appFileWriteAction, UserSub: "u-afw", Status: "failed",
			Payload:   `{"app":"cloudapp","path":".xpcloud.yaml","op":"write","content":"x: 1"}`,
			CreatedAt: now, CompletedAt: &now},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	dir, direct, via, _ := ownerWriteTarget("u-afw", "cloudapp")
	if direct || !via || dir != "" {
		t.Fatalf("installed cloud app: dir=%q direct=%v via=%v; want viaIntent", dir, direct, via)
	}
	if !ownerCanEdit("u-afw", "cloudapp") {
		t.Fatal("editable must be true for a queued-write install")
	}
	b, del, found := appFileOverlay("u-afw", "cloudapp", "prompts/p.md")
	if !found || del || string(b) != "EDITED" {
		t.Fatalf("overlay = %q found=%v deleted=%v; want the applied edit", b, found, del)
	}
	if _, _, found := appFileOverlay("u-afw", "cloudapp", appFileSpecRel); found {
		t.Fatal("a FAILED write must not overlay")
	}

	id, norm, err := queueAppFileWrite("u-afw", "cloudapp", "prompts/q.md", "write", "hello", "abc")
	if err != nil || id == "" || norm != "prompts/q.md" {
		t.Fatalf("queue: id=%q norm=%q err=%v", id, norm, err)
	}
	var got models.MeAppIntent
	if err := db.Where("id = ?", id).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Action != appFileWriteAction || got.Status != "pending" ||
		!strings.Contains(got.Payload, `"base_sha":"abc"`) || !strings.Contains(got.Payload, `"content":"hello"`) {
		t.Fatalf("queued row wrong: %+v", got)
	}
	if _, _, err := queueAppFileWrite("u-afw", "cloudapp", "ui/home.md", "write", "x", ""); err != errAppFilePath {
		t.Fatalf("a path the picker refuses must not be queued; err=%v", err)
	}
}

// Source-level guard, as me_loop_patch_intent_test.go: what regressed is a
// CHOICE — write it yourself vs queue it for the process that can — and a
// reader can undo it in one line.
func TestOwnerFileWritesGoThroughAnIntent(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_app_prompts.go", "MeUpdateAppPrompt", `enqueueAppFileWrite(c, userID, app, promptDirRel+"/"+name, "write"`},
		{"me_app_prompts.go", "MeDeleteAppPrompt", `enqueueAppFileWrite(c, userID, app, promptDirRel+"/"+name, "delete"`},
		{"me_app_config.go", "MeUpdateAppConfig", `enqueueAppFileWrite(c, userID, app, appFileSpecRel`},
		{"me_app_ui.go", "updateAppSurface", `enqueueAppFileWrite(c, userID, app, rel`},
		{"me_agent_app_ops.go", "toolAppUISet", `queuedToolResult(userID, app, rel`},
		{"me_agent_app_ops.go", "toolAppPromptSet", `queuedToolResult(userID, app, promptDirRel`},
		{"me_agent_app_ops.go", "toolAppPromptReset", `queuedToolResult(userID, app, promptDirRel`},
		{"me_agent_tools_observability.go", "toolAppConfigSet", `queuedToolResult(userID, app, appFileSpecRel`},
	} {
		block := funcBlock(t, c.file, c.fn)
		if !strings.Contains(block, c.marker) {
			t.Errorf("%s no longer queues an %s intent; on UKS it will fail for every owner, "+
				"because identity mounts no tenant volume", c.fn, appFileWriteAction)
		}
		if !strings.Contains(block, "ownerWriteTarget(") {
			t.Errorf("%s does not route through ownerWriteTarget", c.fn)
		}
		if strings.Contains(block, "resolveOwnedAppDir(") {
			t.Errorf("%s calls resolveOwnedAppDir directly — that 403s every cloud install", c.fn)
		}
	}
	// The queue helpers carry the action name; the handlers above reach it
	// only through them.
	if src := loopPatchSrc(t, "me_app_file_intent.go"); !strings.Contains(src, `appFileWriteAction = "app_file_write"`) {
		t.Error("the intent action must be app_file_write — the name the scheduler's picker dispatches on")
	}
}

// Readers must see the overlay, or a queued save looks lost on reload.
func TestOwnerFileReadsApplyTheOverlay(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_app_prompts.go", "listAppPrompts", "appFileOverlayNames("},
		{"me_app_prompts.go", "readAppPrompt", "appFileOverlay("},
		{"me_app_prompts.go", "MeAppPrompts", "listAppPrompts("},
		{"me_app_prompts.go", "MeAppPrompt", "readAppPrompt("},
		{"me_app_config.go", "readAppSpecBytes", "appFileOverlay("},
		{"me_app_config.go", "MeAppConfig", "readAppSpecBytes("},
		{"me_app_ui.go", "serveAppSurface", "appFileOverlays("},
		{"me_agent_app_ops.go", "toolAppUIGet", "appFileOverlay("},
		{"me_agent_app_ops.go", "toolAppPromptList", "listAppPrompts("},
		{"me_agent_app_ops.go", "toolAppPromptGet", "readAppPrompt("},
		{"me_agent_tools_observability.go", "toolAppConfigGet", "readAppSpecBytes("},
	} {
		if !strings.Contains(funcBlock(t, c.file, c.fn), c.marker) {
			t.Errorf("%s does not apply the app_file_write overlay (%s)", c.fn, c.marker)
		}
	}
}

func funcBlock(t *testing.T, file, fn string) string {
	t.Helper()
	src := loopPatchSrc(t, file)
	i := strings.Index(src, "func "+fn+"(")
	if i < 0 {
		t.Fatalf("%s not found in %s", fn, file)
	}
	block := src[i:]
	if j := strings.Index(block[1:], "\nfunc "); j > 0 {
		block = block[:j]
	}
	return block
}
