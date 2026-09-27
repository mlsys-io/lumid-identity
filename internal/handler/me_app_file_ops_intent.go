package handler

// The rest of the owner writes — control signals, journal rows, feedback,
// improvements, review decisions, draft edits — for the case where identity
// cannot see the install.
//
// me_app_file_intent.go moved the prompt/config/UI editors onto an
// app_file_write intent; the same reasoning applies to every other handler that
// appended to or edited a file under the tenant's install: identity mounts no
// tenant volume; the scheduler can see the disk. resolveAppDir hands a cloud
// pod the materialised bundle cache, so those handlers "succeeded" into a
// pod-local copy of the PUBLISHED tree that no runner reads and that dies with
// the pod — and reported 200.
//
// The picker's app_file_write takes two extra ops for these:
//
//   - append:   `content` is exactly ONE JSON record; the picker adds the
//     newline. Capped at 16 KB so a record can never be a file.
//   - json_set: `set` is a list of [key_path, value]; only the named keys
//     change, value null deletes. A read-modify-write done HERE would race
//     the runner, which rewrites these files itself.
//
// Both only travel in the batch form ({app, files:[...]}), which is applied
// all-or-nothing — so a feedback row and the journal line that announces it
// either both land or neither does.
//
// `.lumid/...` paths fall back, on the scheduler, to an existing legacy
// `data/...` file on the install; always send the canonical `.lumid/` form.

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

// appFileIntentOps is the picker's (path → ops) table, verbatim. The prompt/UI
// rows repeat appFileIntentPathRes so a batch validates against one table.
var appFileIntentOps = []struct {
	re  *regexp.Regexp
	ops []string
}{
	{regexp.MustCompile(`^prompts/[A-Za-z0-9._-]+\.md$`), []string{"write", "delete"}},
	{regexp.MustCompile(`^\.ui/[A-Za-z0-9._-]+\.(md|ya?ml)$`), []string{"write", "delete"}},
	{regexp.MustCompile(`^ui/[A-Za-z0-9._-]+\.ya?ml$`), []string{"write", "delete"}},
	{regexp.MustCompile(`^\.xpcloud\.yaml$`), []string{"write"}},
	{regexp.MustCompile(`^\.lumid/control/signals\.jsonl$`), []string{"append"}},
	{regexp.MustCompile(`^\.lumid/journal\.jsonl$`), []string{"append"}},
	{regexp.MustCompile(`^data/improvements\.jsonl$`), []string{"append"}},
	{regexp.MustCompile(`^\.lumid/cycles/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/feedback\.jsonl$`), []string{"append"}},
	{regexp.MustCompile(`^data/approved_actions\.json$`), []string{"json_set"}},
	{regexp.MustCompile(`^data/step_instructions_pending\.json$`), []string{"json_set"}},
	{regexp.MustCompile(`^\.lumid/outbox/[A-Za-z0-9._-]+/drafts/[A-Za-z0-9._-]+\.json$`), []string{"json_set"}},
}

// Canonical targets of the handlers in this file.
const (
	signalsRel       = ".lumid/control/signals.jsonl"
	journalRel       = ".lumid/journal.jsonl"
	improvementsRel  = "data/improvements.jsonl"
	approvedActsRel  = "data/approved_actions.json"
	stepInstrPendRel = "data/step_instructions_pending.json"

	appFileAppendMaxBytes = 16 * 1024 // picker cap for one appended record
	appFileBatchMax       = 16
	appFileJSONSetMax     = 8
	appFileKeyPathMax     = 3
)

var (
	errAppFileOp    = errors.New("op not allowed for this path")
	errAppFileBatch = errors.New("a batch carries 1-16 files")
	errAppFileSet   = errors.New("set must be 1-8 [key_path, value] pairs, key_path 1-3 non-empty strings")
)

// appFileIntentOpOK reports whether the picker accepts `op` on `rel`.
func appFileIntentOpOK(rel, op string) bool {
	for _, row := range appFileIntentOps {
		if row.re.MatchString(rel) {
			for _, o := range row.ops {
				if o == op {
					return true
				}
			}
			return false
		}
	}
	return false
}

var safeSegRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// safeSeg is one path segment the picker's `<seg>` accepts — minus "." and
// "..", which its regex would also match and which name no cycle or loop.
func safeSeg(s string) bool {
	return safeSegRe.MatchString(s) && s != "." && s != ".."
}

// cycleFeedbackRel is the canonical feedback.jsonl for one cycle, or "" when
// loop/ts are not single safe segments.
func cycleFeedbackRel(loop, ts string) string {
	if !safeSeg(loop) || !safeSeg(ts) {
		return ""
	}
	return ".lumid/cycles/" + loop + "/" + ts + "/feedback.jsonl"
}

// appendOp builds one `append` entry. The record is marshalled here — json
// escapes newlines inside strings, so the line is one line — and refused
// over 16 KB rather than handed to a picker that would refuse it later.
func appendOp(rel string, rec any) (map[string]any, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if len(b) > appFileAppendMaxBytes {
		return nil, errAppFileTooBig
	}
	return map[string]any{"path": rel, "op": "append", "content": string(b)}, nil
}

// jsonSetPair is one `set` entry: [key_path, value]. A nil value deletes.
func jsonSetPair(value any, keyPath ...string) []any {
	return []any{keyPath, value}
}

// jsonSetOp builds one `json_set` entry and checks the shape the picker wants.
func jsonSetOp(rel string, sets ...[]any) (map[string]any, error) {
	if len(sets) == 0 || len(sets) > appFileJSONSetMax {
		return nil, errAppFileSet
	}
	for _, s := range sets {
		if len(s) != 2 {
			return nil, errAppFileSet
		}
		kp, ok := s[0].([]string)
		if !ok || len(kp) == 0 || len(kp) > appFileKeyPathMax {
			return nil, errAppFileSet
		}
		for _, k := range kp {
			if k == "" {
				return nil, errAppFileSet
			}
		}
	}
	return map[string]any{"path": rel, "op": "json_set", "set": sets}, nil
}

// writeOp builds one `write` entry (prompt/UI/spec) for a batch.
func writeOp(rel, content, baseSHA string) map[string]any {
	return map[string]any{"path": normAppFileRel(rel), "op": "write", "content": content, "base_sha": baseSHA}
}

// queueAppFileBatch validates and enqueues one batch app_file_write. The
// picker applies it all-or-nothing.
func queueAppFileBatch(userSub, app string, files []map[string]any) (string, error) {
	if len(files) == 0 || len(files) > appFileBatchMax {
		return "", errAppFileBatch
	}
	for _, f := range files {
		rel, _ := f["path"].(string)
		op, _ := f["op"].(string)
		if normAppFileRel(rel) != rel || !appFileIntentOpOK(rel, op) {
			return "", errAppFileOp
		}
		if content, _ := f["content"].(string); op == "write" {
			limit := appFileIntentMaxBytes
			if rel == appFileSpecRel {
				limit = appFileIntentSpecMaxBytes
			}
			if len(content) > limit {
				return "", errAppFileTooBig
			}
		}
	}
	return insertIntent(appFileWriteAction, userSub, map[string]any{"app": app, "files": files})
}

// queueAppFileOps is the one-call form: build errors and enqueue errors come
// back the same way, so a handler maps them to a status once.
func queueAppFileOps(userSub, app string, build func() ([]map[string]any, error)) (string, error) {
	files, err := build()
	if err != nil {
		return "", err
	}
	return queueAppFileBatch(userSub, app, files)
}

// appFileOpsStatus maps a queue error to the HTTP answer.
func appFileOpsStatus(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errAppFileTooBig):
		fail(c, http.StatusRequestEntityTooLarge, 1413, "record exceeds 16 KB")
	case errors.Is(err, errAppFileOp), errors.Is(err, errAppFileSet), errors.Is(err, errAppFileBatch):
		fail(c, http.StatusBadRequest, 1400, err.Error())
	default:
		fail(c, http.StatusInternalServerError, 1500, "queue intent: "+err.Error())
	}
}

// respondQueued answers 202 for any queued owner write. It makes no claim the
// write landed: the scheduler applies it, and may refuse it.
func respondQueued(c *gin.Context, id string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data["intent_id"] = id
	data["status"] = "pending"
	data["queued"] = true
	c.JSON(http.StatusAccepted, gin.H{"ret_code": 0, "message": "queued", "data": data})
}

// queuedOpsToolResult is the chat-tool twin of respondQueued.
func queuedOpsToolResult(id string, extra map[string]any) map[string]any {
	out := map[string]any{
		"intent_id": id, "state": "queued", "queued": true,
		"note": "QUEUED for the scheduler, which applies it to your install (a few seconds). " +
			"It has not been applied yet.",
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ownerWriteFail answers the shared (403) / not-installed (404) branches of
// ownerWriteTarget, exactly as the prompt editor does.
func ownerWriteFail(c *gin.Context, shared bool) {
	if shared {
		fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
		return
	}
	fail(c, http.StatusNotFound, 1404, "app not found")
}

// ownerWriteToolFail is ownerWriteFail for the chat tools.
func ownerWriteToolFail(app string, shared bool) (map[string]any, bool) {
	if shared {
		return map[string]any{"error": "this app is operator-shared (read-only) — fork/install your own copy first"}, false
	}
	return map[string]any{"error": "app not found: " + app}, false
}
