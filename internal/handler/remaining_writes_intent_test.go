package handler

// The remaining owner writes — signals, journal rows, feedback, improvements,
// review decisions, loop removal, drafts staged by compose/import, generated
// UI, run marks, eval requests, inbound email — go through an intent when
// identity cannot see the install. identity mounts no tenant volume; the
// scheduler can see the disk. Every handler below used to write into this
// pod's own filesystem (or the materialised bundle cache) and report success.
//
// Source-level guards for the CHOICE (queue it vs write it yourself), unit
// tests for the pure builders, and two MySQL-backed tests (skipped without
// TEST_MYSQL_DSN): persona round-trip, and the intent payload column widening.

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// fnBlock returns the source of one top-level func in file.
func fnBlock(t *testing.T, file, fn string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	src := string(b)
	i := strings.Index(src, "func "+fn+"(")
	if i < 0 {
		t.Fatalf("%s not found in %s", fn, file)
	}
	block := src[i:]
	if j := strings.Index(block[1:], "\nfunc "); j > 0 {
		block = block[:j+1]
	}
	return block
}

func TestRemainingWritesGoThroughAnIntent(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_agent_helpers.go", "agentStopLoop", `"stop_loop"`},
		// Signals: a me_app_signals row the runner claims at cycle start
		// (me_app_signals_db.go), not a queued file append.
		{"me_trajectory_signal.go", "MeTrajectorySignal", `insertAppSignal(`},
		{"me_agent_app_ops.go", "toolBranchRun", `insertAppSignal(`},
		{"me_cycles.go", "MeCycleFeedback", `queueCycleFeedback(`},
		{"me_cycles.go", "cycleFeedbackOps", `appendOp(journalRel`},
		{"me_cycles.go", "cycleFeedbackOps", `appendOp(improvementsRel`},
		{"me_agent_helpers.go", "agentWriteFeedback", `cycleFeedbackOps(`},
		{"me_improvements.go", "appendImprovement", `appendOp(improvementsRel`},
		{"me_improvements.go", "MeFeedbackSave", `ownerWriteTarget(`},
		{"me_runs.go", "MeRunMark", `appendOp(journalRel`},
		{"me_cycle_review.go", "applyCycleReview", `jsonSetOp(`},
		{"me_workflows.go", "removeLoopFromApp", `"remove_loop"`},
		{"me_agent_workflows.go", "toolAddSkillToWorkflow", `"add_skill"`},
		{"me_agent_workflows.go", "stageDraftApp", `"stage_app"`},
		{"me_agent_workflows.go", "stageDraftApp", `upsertStoredAppSpec(`},
		{"me_agent_workflows.go", "toolComposeWorkflow", `stageDraftApp(`},
		{"me_agent_workflows.go", "composeTradingDraft", `stageDraftApp(`},
		{"me_workflows.go", "MeImportFromN8n", `stageDraftApp(`},
		{"me_workflows.go", "MeImportFromN8n", `tenantInstalledAppNames(`},
		{"me_validate.go", "MeValidateWorkflow", `storedAppSpec(`},
		{"me_app_ui_gen.go", "generateAppUIPage", `ownerWriteTarget(`},
		{"me_app_ui_gen.go", "generateAppUIPage", `queueAppFileBatch(`},
		{"me_trajectory_ops.go", "meRunMark", `"trajectory_mark"`},
		{"me_agent_app_ops.go", "toolRunMark", `"trajectory_mark"`},
		{"me_mind.go", "queueSkillEval", `"enqueue_eval"`},
		{"me_mind.go", "MeMindEvaluate", `queueSkillEval(`},
		{"me_agent_workflows.go", "toolTriggerEvaluation", `queueSkillEval(`},
		{"power_automate.go", "InboxPowerAutomateReceive", `"inbox_drop"`},
		{"me_app_skills.go", "MeAppAddSkill", `ownerWriteTarget(`},
	} {
		if !strings.Contains(fnBlock(t, c.file, c.fn), c.marker) {
			t.Errorf("%s no longer contains %s. If it has gone back to writing the file "+
				"itself it will write into this pod, because identity mounts no tenant volume",
				c.fn, c.marker)
		}
	}
}

func TestRemovedPodLocalWrites(t *testing.T) {
	for _, c := range []struct{ file, fn, forbidden string }{
		{"me_agent_helpers.go", "agentStopLoop", "os.WriteFile("},
		{"me_agent_helpers.go", "agentStopLoop", "resolveAppDir("},
		{"me_mind.go", "MeMindEvaluate", `"eval-queue.jsonl"`},
		{"me_agent_workflows.go", "toolTriggerEvaluation", `"eval-queue.jsonl"`},
		{"power_automate.go", "InboxPowerAutomateReceive", "os.WriteFile("},
		{"me_agent_personas.go", "MePersonaSave", "os.WriteFile("},
		{"me_agent_personas.go", "MePersonaDelete", "os.Remove("},
		{"me_improvements.go", "improvementsPath", "os.MkdirAll("},
	} {
		if strings.Contains(fnBlock(t, c.file, c.fn), c.forbidden) {
			t.Errorf("%s reaches for %s — that disk is not this pod's", c.fn, c.forbidden)
		}
	}
	src, _ := os.ReadFile("me_app_ui_gen.go")
	if strings.Contains(string(src), "func writeSurfaceAndRespond(") {
		t.Error("writeSurfaceAndRespond is back; it had no callers and wrote into resolveAppDir")
	}
}

// The picker's (path → ops) table, mirrored.
func TestAppFileIntentOpTable(t *testing.T) {
	for _, c := range []struct {
		rel, op string
		want    bool
	}{
		{"prompts/a.md", "write", true},
		{"prompts/a.md", "delete", true},
		{"prompts/a.md", "append", false},
		{".xpcloud.yaml", "write", true},
		{".xpcloud.yaml", "delete", false},
		{".ui/page.yaml", "write", true},
		{".lumid/control/signals.jsonl", "append", true},
		{".lumid/control/signals.jsonl", "write", false},
		{"data/control/signals.jsonl", "append", false}, // canonical form only
		{".lumid/journal.jsonl", "append", true},
		{"data/improvements.jsonl", "append", true},
		{".lumid/cycles/main/20260101T000000Z/feedback.jsonl", "append", true},
		{".lumid/cycles/main/feedback.jsonl", "append", false},
		{"data/approved_actions.json", "json_set", true},
		{"data/step_instructions_pending.json", "json_set", true},
		{"data/approved_actions.json", "write", false},
		{".lumid/outbox/20260101T000000Z/drafts/x.json", "json_set", true},
		{"commands/run.py", "write", false},
	} {
		if got := appFileIntentOpOK(c.rel, c.op); got != c.want {
			t.Errorf("appFileIntentOpOK(%q,%q)=%v want %v", c.rel, c.op, got, c.want)
		}
	}
}

func TestSafeSegAndCycleFeedbackRel(t *testing.T) {
	for s, want := range map[string]bool{
		"main": true, "20260101T000000Z_retry": true, "a.b-c": true,
		"": false, ".": false, "..": false, "a/b": false, "a b": false, `a\b`: false,
	} {
		if safeSeg(s) != want {
			t.Errorf("safeSeg(%q) != %v", s, want)
		}
	}
	if got := cycleFeedbackRel("main", "20260101T000000Z"); got != ".lumid/cycles/main/20260101T000000Z/feedback.jsonl" {
		t.Errorf("cycleFeedbackRel = %q", got)
	}
	if cycleFeedbackRel("..", "x") != "" || cycleFeedbackRel("main", "a/b") != "" {
		t.Error("cycleFeedbackRel accepted an unsafe segment")
	}
}

func TestAppendOpIsOneRecordAndCapped(t *testing.T) {
	op, err := appendOp(journalRel, map[string]any{"note": "two\nlines"})
	if err != nil {
		t.Fatal(err)
	}
	content := op["content"].(string)
	if strings.Contains(content, "\n") {
		t.Errorf("append content spans lines: %q", content)
	}
	var back map[string]any
	if json.Unmarshal([]byte(content), &back) != nil || back["note"] != "two\nlines" {
		t.Errorf("append content is not the record: %q", content)
	}
	if op["op"] != "append" || op["path"] != journalRel {
		t.Errorf("bad op: %v", op)
	}
	_, err = appendOp(signalsRel, map[string]any{"note": strings.Repeat("x", appFileAppendMaxBytes)})
	if !errors.Is(err, errAppFileTooBig) {
		t.Errorf("a >16 KB record was not refused: %v", err)
	}
}

func TestJSONSetOpShape(t *testing.T) {
	op, err := jsonSetOp(stepInstrPendRel, jsonSetPair("text", "loop", "step"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(op)
	if string(raw) != `{"op":"json_set","path":"data/step_instructions_pending.json","set":[[["loop","step"],"text"]]}` {
		t.Errorf("wire shape: %s", raw)
	}
	for name, sets := range map[string][][]any{
		"none":     nil,
		"empty kp": {jsonSetPair(1)},
		"blank":    {jsonSetPair(1, "a", "")},
		"deep":     {jsonSetPair(1, "a", "b", "c", "d")},
		"too many": {jsonSetPair(1, "a"), jsonSetPair(1, "b"), jsonSetPair(1, "c"), jsonSetPair(1, "d"),
			jsonSetPair(1, "e"), jsonSetPair(1, "f"), jsonSetPair(1, "g"), jsonSetPair(1, "h"), jsonSetPair(1, "i")},
	} {
		if _, err := jsonSetOp(approvedActsRel, sets...); !errors.Is(err, errAppFileSet) {
			t.Errorf("%s: want errAppFileSet, got %v", name, err)
		}
	}
	// null deletes — a nil value must survive as JSON null.
	op, _ = jsonSetOp(approvedActsRel, jsonSetPair(nil, "k"))
	raw, _ = json.Marshal(op)
	if !strings.Contains(string(raw), `[["k"],null]`) {
		t.Errorf("nil value not sent as null: %s", raw)
	}
}

func TestQueueAppFileBatchValidatesBeforeInsert(t *testing.T) {
	// No DB: every case here must be refused before insertIntent is reached.
	if _, err := queueAppFileBatch("u", "app", nil); !errors.Is(err, errAppFileBatch) {
		t.Errorf("empty batch: %v", err)
	}
	many := make([]map[string]any, appFileBatchMax+1)
	for i := range many {
		many[i] = map[string]any{"path": journalRel, "op": "append", "content": "{}"}
	}
	if _, err := queueAppFileBatch("u", "app", many); !errors.Is(err, errAppFileBatch) {
		t.Errorf("17 files: %v", err)
	}
	for _, f := range []map[string]any{
		{"path": "data/journal.jsonl", "op": "append", "content": "{}"},
		{"path": journalRel, "op": "write", "content": "{}"},
		{"path": "./.lumid/journal.jsonl", "op": "append", "content": "{}"},
	} {
		if _, err := queueAppFileBatch("u", "app", []map[string]any{f}); !errors.Is(err, errAppFileOp) {
			t.Errorf("%v: want errAppFileOp, got %v", f, err)
		}
	}
	big := writeOp(appFileSpecRel, strings.Repeat("a", appFileIntentSpecMaxBytes+1), "")
	if _, err := queueAppFileBatch("u", "app", []map[string]any{big}); !errors.Is(err, errAppFileTooBig) {
		t.Errorf("oversize spec: %v", err)
	}
}

func TestCycleFeedbackOps(t *testing.T) {
	entry := cycleFeedbackEntry("u1", "app", "main", "20260101T000000Z", 1, "good", "tenant")
	imp := cycleFeedbackImprovement(meCycleFeedbackBody{App: "app", Loop: "main", Ts: "20260101T000000Z", Rating: 1, Note: "good"})
	ops, err := cycleFeedbackOps("main", "20260101T000000Z", entry, imp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".lumid/cycles/main/20260101T000000Z/feedback.jsonl", journalRel, improvementsRel}
	if len(ops) != len(want) {
		t.Fatalf("got %d ops", len(ops))
	}
	for i, w := range want {
		if ops[i]["path"] != w || ops[i]["op"] != "append" || !appFileIntentOpOK(w, "append") {
			t.Errorf("op %d = %v, want append %s", i, ops[i], w)
		}
	}
	var row improvementEvent
	_ = json.Unmarshal([]byte(ops[2]["content"].(string)), &row)
	if row.ID == "" || row.Ts == "" || row.Axis != "examples" || row.Verb != "good" {
		t.Errorf("improvement row not prepared: %+v", row)
	}
	if ops, _ := cycleFeedbackOps("main", "ts", entry, nil); len(ops) != 2 {
		t.Errorf("chat feedback (no improvement) should be 2 ops, got %d", len(ops))
	}
	if _, err := cycleFeedbackOps("..", "ts", entry, nil); err == nil {
		t.Error("unsafe loop accepted")
	}
}

func TestCycleReviewSet(t *testing.T) {
	now := time.Date(2026, 9, 27, 1, 2, 3, 0, time.UTC)
	rel, set, code, _ := cycleReviewSet("main", cycleReviewBody{Decision: "approve", StepID: "act"}, now)
	raw, _ := json.Marshal(set)
	if code != 0 || rel != approvedActsRel || string(raw) != `[["main:act"],{"approved_at":"2026-09-27T01:02:03Z"}]` {
		t.Errorf("approve: rel=%s set=%s code=%d", rel, raw, code)
	}
	rel, set, code, _ = cycleReviewSet("main", cycleReviewBody{Decision: "approve", OutboxRef: "x:y"}, now)
	raw, _ = json.Marshal(set)
	if code != 0 || !strings.HasPrefix(string(raw), `[["x:y"]`) {
		t.Errorf("approve by outbox_ref: %s", raw)
	}
	rel, set, code, _ = cycleReviewSet("main", cycleReviewBody{Decision: "revamp", StepID: "s1", StepInstructions: "do X"}, now)
	raw, _ = json.Marshal(set)
	if code != 0 || rel != stepInstrPendRel || string(raw) != `[["main","s1"],"do X"]` {
		t.Errorf("revamp: rel=%s set=%s", rel, raw)
	}
	if rel, _, code, _ = cycleReviewSet("main", cycleReviewBody{Decision: "dismiss"}, now); rel != "" || code != 0 {
		t.Error("dismiss must be a no-op")
	}
	for _, b := range []cycleReviewBody{{Decision: "approve"}, {Decision: "edit", StepID: "s"}, {Decision: "nope"}} {
		if _, _, code, _ := cycleReviewSet("main", b, now); code != 400 {
			t.Errorf("%+v: want 400, got %d", b, code)
		}
	}
	// Every non-empty result is something the picker accepts.
	for _, b := range []cycleReviewBody{{Decision: "approve", StepID: "a"}, {Decision: "edit", StepID: "a", StepInstructions: "x"}} {
		rel, set, _, _ := cycleReviewSet("main", b, now)
		if _, err := jsonSetOp(rel, set); err != nil || !appFileIntentOpOK(rel, "json_set") {
			t.Errorf("%+v does not build a valid json_set: %v", b, err)
		}
	}
}

func TestPatchSpecUISurfacePage(t *testing.T) {
	in := []byte("name: app\nui:\n  surface:\n    markdown: ui/home.md\n    native: x\nloops:\n  - name: main\n")
	out, err := patchSpecUISurfacePage(in, ".ui/page.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	surface := doc["ui"].(map[string]any)["surface"].(map[string]any)
	if surface["page"] != ".ui/page.yaml" || surface["markdown"] != nil || surface["native"] != nil {
		t.Errorf("surface = %v", surface)
	}
	if doc["name"] != "app" || len(doc["loops"].([]any)) != 1 {
		t.Errorf("unrelated keys changed: %v", doc)
	}
	if out, err := patchSpecUISurfacePage([]byte("name: a\n"), ".ui/page.yaml"); err != nil || !strings.Contains(string(out), "page: .ui/page.yaml") {
		t.Errorf("no ui block: %s %v", out, err)
	}
	if _, err := patchSpecUISurfacePage([]byte(""), ".ui/page.yaml"); err == nil {
		t.Error("an empty spec must not be patched into a new one")
	}
}

func TestSpecLoopsWithout(t *testing.T) {
	var doc map[string]any
	_ = yaml.Unmarshal([]byte("loops:\n  - name: a\n  - name: b\n"), &doc)
	kept, status, _, _ := specLoopsWithout(doc, "app", "a")
	if status != 200 || len(kept) != 1 {
		t.Errorf("remove a: status=%d kept=%v", status, kept)
	}
	if _, status, _, _ := specLoopsWithout(doc, "app", "zz"); status != 404 {
		t.Errorf("unknown loop: %d", status)
	}
	_ = yaml.Unmarshal([]byte("loops:\n  - name: only\n"), &doc)
	if _, status, code, _ := specLoopsWithout(doc, "app", "only"); status != 409 || code != 1409 {
		t.Errorf("last loop: %d/%d", status, code)
	}
}

func TestManifestFromSpecValidatesLikeTheWrittenOne(t *testing.T) {
	spec := []byte(buildDraftXpcloudYaml("my-flow", "do things", "", []string{"fetch"}))
	if ck := validateManifestLintBytes(manifestFromSpec(spec), nil); ck.Status != "pass" {
		t.Errorf("manifest rebuilt from a composed spec fails lint: %+v", ck)
	}
	if ck := validatePipelineShapeBytes(spec, nil); ck.Check != "pipeline_shape" {
		t.Errorf("pipeline check: %+v", ck)
	}
	if ck := validateManifestLintBytes(manifestFromSpec([]byte(":\n\t- bad")), nil); ck.Status != "fail" {
		t.Error("unparseable spec passed manifest lint")
	}
}

func TestSkillEvalArgsAndTrajectoryPayload(t *testing.T) {
	for _, c := range []struct {
		skill, app string
		ok         bool
	}{
		{"community/fetch", "quant-research", true},
		{"fetch", "a", true},
		{"../x", "a", false},
		{"fetch", "a/b", false},
		{"fetch", ".hidden", false},
		{"", "a", false},
	} {
		if skillEvalArgsOK(c.skill, c.app) != c.ok {
			t.Errorf("skillEvalArgsOK(%q,%q) != %v", c.skill, c.app, c.ok)
		}
	}
	p := trajectoryMarkPayload("promote", "app", "20260101T000000Z", "")
	if _, has := p["loop"]; has || p["verb"] != "promote" || p["app"] != "app" || p["ts"] != "20260101T000000Z" {
		t.Errorf("payload = %v", p)
	}
	if trajectoryMarkPayload("discard", "a", "t", "main")["loop"] != "main" {
		t.Error("loop dropped")
	}
}

// ── MySQL-backed ────────────────────────────────────────────────────────────

func openTestMySQL(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping MySQL-backed test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	return db
}

func TestPersonaStoreRoundTripDB(t *testing.T) {
	db := openTestMySQL(t)
	if err := db.AutoMigrate(&models.MePersona{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MePersona{})
	prev := common.DB
	common.DB = db
	defer func() { common.DB = prev }()

	now := time.Now().UTC().Truncate(time.Second)
	p := &persona{ID: newPersonaID(), Name: "Reviewer", Icon: "R", SystemPrompt: "be terse",
		AllowedTools: []string{"read_file", "grep"}, PreferredModel: "m1",
		CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)}
	if err := personaStoreSave("user-A", p); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadPersona("user-A", p.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Name != "Reviewer" || got.SystemPrompt != "be terse" || len(got.AllowedTools) != 2 ||
		got.AllowedTools[1] != "grep" || got.PreferredModel != "m1" || got.UpdatedAt != p.UpdatedAt {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// Another user cannot read it by id.
	if other, _ := loadPersona("user-B", p.ID); other != nil {
		t.Error("persona readable across users")
	}
	// Update in place.
	got.Name = "Reviewer 2"
	if err := personaStoreSave("user-A", got); err != nil {
		t.Fatal(err)
	}
	list, _ := personaStoreList("user-A")
	if len(list) != 1 || list[0].Name != "Reviewer 2" {
		t.Errorf("list after update: %+v", list)
	}
	// Prune keeps the newest N.
	for i := 0; i < 3; i++ {
		q := &persona{ID: newPersonaID(), Name: "p", SystemPrompt: "x",
			CreatedAt: now.Format(time.RFC3339),
			UpdatedAt: now.Add(time.Duration(i+1) * time.Minute).Format(time.RFC3339)}
		_ = personaStoreSave("user-A", q)
	}
	prunePersonas("user-A", 2)
	list, _ = personaStoreList("user-A")
	if len(list) != 2 || list[0].UpdatedAt <= list[1].UpdatedAt {
		for _, p := range list {
			t.Logf("kept %s %s", p.ID, p.UpdatedAt)
		}
		t.Errorf("prune/order: %d kept", len(list))
	}
	// Delete: found once, then not.
	if found, err := personaStoreDelete("user-A", list[0].ID); !found || err != nil {
		t.Errorf("delete: %v %v", found, err)
	}
	if found, _ := personaStoreDelete("user-A", list[0].ID); found {
		t.Error("second delete reported found")
	}
}

// legacyMeAppIntent is me_app_intents as it exists in prod today: TEXT payload
// and result.
type legacyMeAppIntent struct {
	ID          string `gorm:"column:id;size:36;primaryKey"`
	Action      string `gorm:"column:action;size:32;not null"`
	UserSub     string `gorm:"column:user_sub;size:36;not null"`
	Payload     string `gorm:"column:payload;type:text"`
	Bearer      string `gorm:"column:bearer;type:text"`
	Status      string `gorm:"column:status;size:16;not null;default:pending"`
	Result      string `gorm:"column:result;type:text"`
	Attempts    int    `gorm:"column:attempts;not null;default:0"`
	CreatedAt   time.Time
	ClaimedAt   *time.Time
	CompletedAt *time.Time
}

func (legacyMeAppIntent) TableName() string { return "me_app_intents" }

// A TEXT payload column must be widened by the startup AutoMigrate — strict
// mode refuses a >64 KB insert rather than truncating it.
func TestMeAppIntentPayloadWidenedByAutoMigrate(t *testing.T) {
	db := openTestMySQL(t)
	if err := db.Migrator().DropTable("me_app_intents"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := db.Migrator().CreateTable(&legacyMeAppIntent{}); err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	colType := func(col string) string {
		var ty string
		db.Raw(`SELECT DATA_TYPE FROM information_schema.COLUMNS
		        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'me_app_intents' AND COLUMN_NAME = ?`, col).Scan(&ty)
		return strings.ToLower(ty)
	}
	if got := colType("payload"); got != "text" {
		t.Fatalf("precondition: payload is %q, want text", got)
	}
	big := `{"app":"a","content":"` + strings.Repeat("x", 100*1024) + `"}`
	// Strict mode: the legacy column refuses it.
	if err := db.Exec("INSERT INTO me_app_intents (id, action, user_sub, payload, status) VALUES (?,?,?,?,?)",
		"pre", "app_file_write", "u", big, "pending").Error; err == nil {
		t.Log("note: legacy TEXT accepted 100 KB — server is not in strict mode")
		db.Exec("DELETE FROM me_app_intents WHERE id = 'pre'")
	}

	if err := models.AutoMigrate(db.Session(&gorm.Session{})); err != nil {
		// Only the intent table is under test; migrate it directly if the full
		// list trips over something unrelated in a throwaway schema.
		if err2 := db.AutoMigrate(&models.MeAppIntent{}); err2 != nil {
			t.Fatalf("automigrate: %v / %v", err, err2)
		}
	}
	for _, col := range []string{"payload", "result"} {
		if got := colType(col); got != "mediumtext" {
			t.Errorf("%s is %q after AutoMigrate, want mediumtext", col, got)
		}
	}
	row := models.MeAppIntent{ID: "big-1", Action: "app_file_write", UserSub: "u", Payload: big, Status: "pending",
		Result: big}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("100 KB insert after widening: %v", err)
	}
	var back models.MeAppIntent
	db.First(&back, "id = ?", "big-1")
	if len(back.Payload) != len(big) || len(back.Result) != len(big) {
		t.Errorf("round-trip lost bytes: %d/%d of %d", len(back.Payload), len(back.Result), len(big))
	}

	// And the real enqueue path carries a batch through it intact.
	prev := common.DB
	common.DB = db
	defer func() { common.DB = prev }()
	op, _ := jsonSetOp(approvedActsRel, jsonSetPair(map[string]any{"approved_at": "t"}, "main:act"))
	id, err := queueAppFileBatch("u", "app", []map[string]any{op, writeOp("prompts/p.md", strings.Repeat("y", 200*1024), "")})
	if err != nil {
		t.Fatalf("queue 200 KB batch: %v", err)
	}
	var q models.MeAppIntent
	db.First(&q, "id = ?", id)
	var payload struct {
		App   string           `json:"app"`
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal([]byte(q.Payload), &payload); err != nil || payload.App != "app" || len(payload.Files) != 2 {
		t.Fatalf("queued payload: %v %+v", err, payload)
	}
	if set, _ := json.Marshal(payload.Files[0]["set"]); string(set) != `[[["main:act"],{"approved_at":"t"}]]` {
		t.Errorf("json_set on the wire: %s", set)
	}
	db.Where("1 = 1").Delete(&models.MeAppIntent{})
}
