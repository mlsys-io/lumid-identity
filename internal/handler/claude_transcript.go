package handler

// Claude account-pool session recording.
//
// Write path (bridge, from claude-proxy):
//   POST /api/v1/internal/claude-transcript
//
// Read paths:
//   GET  /api/v1/me/claude-sessions            (owner: list own sessions)
//   GET  /api/v1/me/claude-sessions/:conv      (owner: full reconstructed turns)
//   GET  /api/v1/me/claude-recording           (owner: recording on/off)
//   POST /api/v1/me/claude-recording {enabled}
//   GET  /api/v1/admin/claude-sessions         (super_admin: all users)
//   GET  /api/v1/admin/claude-sessions/:conv   (super_admin: any session)
//
// Storage is delta-compacted (see models/claude_transcript.go): each turn keeps
// only the messages added since the previous turn, so a long conversation costs
// O(total messages) not O(turns × messages).

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func gzipBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func gunzipBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer r.Close()
	out, _ := io.ReadAll(r)
	return out
}

// recordingEnabled reports whether a user has recording on (default true).
func recordingEnabled(userSub string) bool {
	var pref models.ClaudeRecordingPref
	if err := common.DB.Where("user_sub = ?", userSub).First(&pref).Error; err != nil {
		return true // no row → default on
	}
	return pref.Enabled
}

type transcriptBody struct {
	UserSub      string `json:"user_sub" binding:"required"`
	Account      string `json:"account"`
	Endpoint     string `json:"endpoint"`
	Stream       bool   `json:"stream"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	DurationMs   int    `json:"duration_ms"`
	Truncated    bool   `json:"truncated"`
	// FieldBox: account Label of the field-box relay that carried this turn
	// ("dublin", "chicago", …). Empty means it went direct from the cluster.
	FieldBox string `json:"field_box"`
	// ViaRelay: delivery, vs FieldBox's intent. Labeled + via_relay=false is
	// the silent-degradation case worth alerting on.
	ViaRelay bool `json:"via_relay"`
	// SessionID: the proxy's lease stickiness unit (x-claude-code-session-id,
	// or the user sub when the client omits it). Empty from an older proxy.
	SessionID string `json:"session_id"`
	// TRUE wire sizes from the proxy (response counted per-chunk, so unaffected
	// by the transcript cap).
	RequestBytes  int64           `json:"request_bytes"`
	ResponseBytes int64           `json:"response_bytes"`
	Request       json.RawMessage `json:"request"`  // full request JSON
	Response      json.RawMessage `json:"response"` // full response (assembled JSON or raw SSE)
}

// InternalClaudeTranscript stores one turn. Bridge-gated.
func InternalClaudeTranscript(c *gin.Context) {
	var body transcriptBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !recordingEnabled(body.UserSub) {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "recording disabled"})
		return
	}

	// Parse the request to split params from messages[] and derive the conv key.
	var req struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
		System   json.RawMessage   `json:"system"`
		Tools    json.RawMessage   `json:"tools"`
	}
	_ = json.Unmarshal(body.Request, &req)

	convKey := convKeyFor(req.Model, req.Messages)
	m := len(req.Messages)

	// Load or create the session; compute the delta against cum_messages.
	var sess models.ClaudeSession
	isNew := common.DB.Where("conv_key = ?", convKey).First(&sess).Error != nil
	now := time.Now().UTC()
	n := 0
	if !isNew {
		n = sess.CumMessages
	}
	// If the client reset/shrank context, restart the delta from 0.
	if m < n {
		n = 0
	}
	var delta []json.RawMessage
	if m > n {
		delta = req.Messages[n:]
	}
	deltaJSON, _ := json.Marshal(delta)

	// Per-turn request params = everything except messages[].
	metaJSON := stripMessages(body.Request)

	toolCount := countToolUse(body.Response)

	turnIndex := sess.TurnCount // 0-based
	turn := models.ClaudeSessionTurn{
		ConvKey:       convKey,
		TurnIndex:     turnIndex,
		Ts:            now,
		Model:         req.Model,
		Endpoint:      body.Endpoint,
		Stream:        body.Stream,
		InputTokens:   body.InputTokens,
		OutputTokens:  body.OutputTokens,
		ToolUseCount:  toolCount,
		DurationMs:    body.DurationMs,
		Truncated:     body.Truncated,
		FieldBox:      body.FieldBox,
		ViaRelay:      body.ViaRelay,
		SessionID:     body.SessionID,
		RequestBytes:  body.RequestBytes,
		ResponseBytes: body.ResponseBytes,
	}

	// Write blobs to S3 when blobstore is configured; fall back to LONGBLOB.
	if common.Blobs != nil {
		bk := common.TurnBlobKey(convKey, turnIndex)
		if err := putTurnBlobs(bk, metaJSON, deltaJSON, body.Response); err != nil {
			// Log but degrade gracefully — store in DB instead.
			log.Printf("blobstore: put %s failed: %v — falling back to DB", bk, err)
			turn.RequestMetaGz = gzipBytes(metaJSON)
			turn.NewMessagesGz = gzipBytes(deltaJSON)
			turn.ResponseGz = gzipBytes(body.Response)
		} else {
			turn.BlobKey = bk
		}
	} else {
		turn.RequestMetaGz = gzipBytes(metaJSON)
		turn.NewMessagesGz = gzipBytes(deltaJSON)
		turn.ResponseGz = gzipBytes(body.Response)
	}

	if err := common.DB.Create(&turn).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "store turn: "+err.Error())
		return
	}

	// Upsert the session summary.
	if isNew {
		sess = models.ClaudeSession{
			ConvKey: convKey, UserSub: body.UserSub, Account: body.Account,
			Model: req.Model, Title: firstUserText(req.Messages), FirstTs: now,
		}
	}
	sess.Account = body.Account
	sess.FieldBox = body.FieldBox
	sess.ViaRelay = body.ViaRelay
	sess.RequestBytes += body.RequestBytes
	sess.ResponseBytes += body.ResponseBytes
	sess.Model = req.Model
	sess.TurnCount = turnIndex + 1
	sess.CumMessages = m
	sess.InputTokens += int64(body.InputTokens)
	sess.OutputTokens += int64(body.OutputTokens)
	sess.ToolUseCount += toolCount
	sess.LastTs = now
	if err := common.DB.Save(&sess).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "upsert session: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"conv_key": convKey, "turn": turnIndex}})
}

// convKeyFor = sha256(model + first user message text)[:16 hex chars].
func convKeyFor(model string, messages []json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(model))
	h.Write([]byte{0})
	if len(messages) > 0 {
		h.Write([]byte(messageText(messages[0])))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// messageText extracts a message's text content (string or content-block array).
func messageText(raw json.RawMessage) string {
	var m struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(m.Content, &blocks) == nil {
		var b bytes.Buffer
		for _, bl := range blocks {
			if bl.Text != "" {
				b.WriteString(bl.Text)
			}
		}
		return b.String()
	}
	return ""
}

func firstUserText(messages []json.RawMessage) string {
	for _, m := range messages {
		var mm struct {
			Role string `json:"role"`
		}
		_ = json.Unmarshal(m, &mm)
		if mm.Role == "user" {
			t := messageText(m)
			if len(t) > 200 {
				t = t[:200]
			}
			return t
		}
	}
	return ""
}

// stripMessages returns the request JSON with the messages[] key removed.
func stripMessages(request json.RawMessage) []byte {
	var obj map[string]json.RawMessage
	if json.Unmarshal(request, &obj) != nil {
		return request
	}
	delete(obj, "messages")
	out, _ := json.Marshal(obj)
	return out
}

// countToolUse counts tool_use blocks in a response (assembled JSON only; SSE
// bodies return 0, which is acceptable for the summary counter).
func countToolUse(response json.RawMessage) int {
	var r struct {
		Content []struct {
			Type string `json:"type"`
		} `json:"content"`
	}
	if json.Unmarshal(response, &r) == nil && len(r.Content) > 0 {
		n := 0
		for _, b := range r.Content {
			if b.Type == "tool_use" {
				n++
			}
		}
		return n
	}
	// STREAMING turns are not objects. claude-proxy stores raw SSE bytes as a
	// JSON *string* (postTranscript: "SSE responses are raw event-stream bytes
	// -- not valid JSON -- so encode them as a JSON string"), so the unmarshal
	// above always failed and every streaming turn recorded tool_use_count=0.
	// Since Claude Code streams effectively everything, the column was 0 for
	// entire sessions: 75- and 85-turn sessions of heavy tool use both read 0.
	//
	// In the SSE form each tool call appears as one content_block_start whose
	// content_block type is tool_use; count those.
	var sse string
	if json.Unmarshal(response, &sse) != nil {
		return 0
	}
	return strings.Count(sse, `"type":"tool_use"`)
}

// ── read paths ──────────────────────────────────────────────────────────────

type sessionCard struct {
	ConvKey   string `json:"conv_key"`
	UserSub   string `json:"user_sub,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	Account   string `json:"account"`
	// FieldBox = which field-box relay served this session's latest turn
	// ("dublin", "chicago", …); "" = dispatched direct from the cluster.
	FieldBox     string    `json:"field_box"`
	ViaRelay     bool      `json:"via_relay"`
	Model        string    `json:"model"`
	Title        string    `json:"title"`
	TurnCount    int       `json:"turn_count"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	ToolUseCount int       `json:"tool_use_count"`
	FirstTs      time.Time `json:"first_ts"`
	LastTs       time.Time `json:"last_ts"`
}

// subToEmail returns the email for a user_sub, cached in-process.
var (
	subEmailMu    sync.Mutex
	subEmailCache = map[string]string{}
)

func subToEmail(sub string) string {
	if sub == "" {
		return ""
	}
	subEmailMu.Lock()
	if e, ok := subEmailCache[sub]; ok {
		subEmailMu.Unlock()
		return e
	}
	subEmailMu.Unlock()
	var u models.User
	email := ""
	if common.DB.Select("email").Where("id = ?", sub).First(&u).Error == nil {
		email = u.Email
	}
	subEmailMu.Lock()
	subEmailCache[sub] = email
	subEmailMu.Unlock()
	return email
}

func listSessions(c *gin.Context, userSub string) {
	var rows []models.ClaudeSession
	q := common.DB.Order("last_ts DESC").Limit(200)
	if userSub != "" {
		q = q.Where("user_sub = ?", userSub)
	}
	if err := q.Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list: "+err.Error())
		return
	}
	cards := make([]sessionCard, len(rows))
	for i, s := range rows {
		cards[i] = sessionCard{
			ConvKey: s.ConvKey, UserSub: s.UserSub, UserEmail: subToEmail(s.UserSub),
			Account: s.Account, FieldBox: s.FieldBox, ViaRelay: s.ViaRelay, Model: s.Model,
			Title: s.Title, TurnCount: s.TurnCount, InputTokens: s.InputTokens,
			OutputTokens: s.OutputTokens, ToolUseCount: s.ToolUseCount,
			FirstTs: s.FirstTs, LastTs: s.LastTs,
		}
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"sessions": cards, "count": len(cards)}})
}

// getSession reconstructs the full turn-by-turn transcript for one conv key.
// ownerSub != "" restricts to that owner (404 if mismatch).
func getSession(c *gin.Context, ownerSub, convKey string) {
	var sess models.ClaudeSession
	if common.DB.Where("conv_key = ?", convKey).First(&sess).Error != nil {
		fail(c, http.StatusNotFound, 1404, "session not found")
		return
	}
	if ownerSub != "" && sess.UserSub != ownerSub {
		fail(c, http.StatusNotFound, 1404, "session not found")
		return
	}
	// PAGINATED, newest-first. This used to load every turn and fetch each
	// turn's blob from object storage serially: a 517-turn session produced a
	// 72 MB response in 48s, past the client's 30s timeout — and even served,
	// a payload that size is not something a browser should parse or render.
	//
	// Default window is the most recent turns, because that is what you open a
	// transcript to look at. `before` walks backwards for older ones.
	limit := 40
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200 // ~35 MB worst case; the real guard is the default
	}
	before := 0
	hasBefore := false
	if v := c.Query("before"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			before, hasBefore = n, true
		}
	}

	q := common.DB.Where("conv_key = ?", convKey)
	if hasBefore {
		q = q.Where("turn_index < ?", before)
	}
	var turns []models.ClaudeSessionTurn
	// DESC + limit selects the NEWEST window; reversed below so the transcript
	// still reads oldest→newest.
	q.Order("turn_index DESC").Limit(limit).Find(&turns)
	for i, j := 0, len(turns)-1; i < j; i, j = i+1, j-1 {
		turns[i], turns[j] = turns[j], turns[i]
	}

	oldestReturned := 0
	if len(turns) > 0 {
		oldestReturned = turns[0].TurnIndex
	}
	var remaining int64
	rq := common.DB.Model(&models.ClaudeSessionTurn{}).Where("conv_key = ?", convKey)
	if len(turns) > 0 {
		rq = rq.Where("turn_index < ?", oldestReturned)
	} else if hasBefore {
		rq = rq.Where("turn_index < ?", before)
	}
	rq.Count(&remaining)

	type turnOut struct {
		TurnIndex int       `json:"turn_index"`
		Ts        time.Time `json:"ts"`
		Model     string    `json:"model"`
		Endpoint  string    `json:"endpoint"`
		FieldBox  string    `json:"field_box"`
		// ViaRelay: delivery, vs FieldBox's intent. See models/claude_transcript.go.
		ViaRelay     bool            `json:"via_relay"`
		Stream       bool            `json:"stream"`
		InputTokens  int             `json:"input_tokens"`
		OutputTokens int             `json:"output_tokens"`
		ToolUseCount int             `json:"tool_use_count"`
		DurationMs   int             `json:"duration_ms"`
		Truncated    bool            `json:"truncated"`
		RequestMeta  json.RawMessage `json:"request_meta"`
		NewMessages  json.RawMessage `json:"new_messages"`
		Response     json.RawMessage `json:"response"`
	}
	out := make([]turnOut, len(turns))
	for i, t := range turns {
		var metaRaw, msgsRaw, respRaw []byte
		if t.BlobKey != "" && common.Blobs != nil {
			metaRaw, msgsRaw, respRaw = getTurnBlobs(t.BlobKey)
		} else {
			metaRaw = gunzipBytes(t.RequestMetaGz)
			msgsRaw = gunzipBytes(t.NewMessagesGz)
			respRaw = gunzipBytes(t.ResponseGz)
		}
		out[i] = turnOut{
			TurnIndex: t.TurnIndex, Ts: t.Ts, Model: t.Model, Endpoint: t.Endpoint,
			FieldBox: t.FieldBox, ViaRelay: t.ViaRelay, Stream: t.Stream, InputTokens: t.InputTokens, OutputTokens: t.OutputTokens,
			ToolUseCount: t.ToolUseCount, DurationMs: t.DurationMs, Truncated: t.Truncated,
			RequestMeta: rawOrNull(metaRaw),
			NewMessages: rawOrNull(msgsRaw),
			Response:    rawOrNull(respRaw),
		}
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
		"data": gin.H{"session": sessionCard{
			ConvKey: sess.ConvKey, UserSub: sess.UserSub, Account: sess.Account,
			FieldBox: sess.FieldBox, ViaRelay: sess.ViaRelay, Model: sess.Model, Title: sess.Title, TurnCount: sess.TurnCount,
			InputTokens: sess.InputTokens, OutputTokens: sess.OutputTokens,
			ToolUseCount: sess.ToolUseCount, FirstTs: sess.FirstTs, LastTs: sess.LastTs,
		}, "turns": out,
			// Pagination surface. `has_more` + `oldest_turn_index` let the client
			// walk backwards with ?before=<oldest_turn_index>.
			"total_turns":       sess.TurnCount,
			"returned":          len(out),
			"oldest_turn_index": oldestReturned,
			"has_more":          remaining > 0,
			"remaining":         remaining,
		}})
}

func rawOrNull(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}

// putTurnBlobs writes the three gzip blobs to S3 for one turn.
func putTurnBlobs(blobKey string, metaJSON, deltaJSON, response json.RawMessage) error {
	for _, f := range []struct {
		suffix string
		data   []byte
	}{
		{"request_meta.gz", gzipBytes(metaJSON)},
		{"new_messages.gz", gzipBytes(deltaJSON)},
		{"response.gz", gzipBytes(response)},
	} {
		if err := common.Blobs.Put(blobKey+"/"+f.suffix, f.data); err != nil {
			return fmt.Errorf("%s: %w", f.suffix, err)
		}
	}
	return nil
}

// getTurnBlobs retrieves the three gzip blobs from S3 and returns
// (requestMetaJSON, newMessagesJSON, responseJSON). Each may be nil on error.
func getTurnBlobs(blobKey string) (meta, msgs, resp []byte) {
	fetch := func(suffix string) []byte {
		raw, err := common.Blobs.Get(blobKey + "/" + suffix)
		if err != nil {
			log.Printf("blobstore: get %s/%s: %v", blobKey, suffix, err)
			return nil
		}
		return gunzipBytes(raw)
	}
	return fetch("request_meta.gz"), fetch("new_messages.gz"), fetch("response.gz")
}

// deleteTurnBlobs removes a turn's three S3 objects, mirroring putTurnBlobs.
// Returns the number of the three that failed to delete (0 = clean), so the
// caller can tell an incomplete erasure from a clean one instead of assuming
// success — this is the exact gap that let DELETE /claude-sessions/:conv
// remove only the DB index while leaving the real content behind in S3.
func deleteTurnBlobs(blobKey string) int {
	failed := 0
	for _, suffix := range []string{"request_meta.gz", "new_messages.gz", "response.gz"} {
		if err := common.Blobs.Delete(blobKey + "/" + suffix); err != nil {
			log.Printf("blobstore: delete %s/%s: %v", blobKey, suffix, err)
			failed++
		}
	}
	return failed
}

// GET /api/v1/me/claude-sessions
func MeClaudeSessions(c *gin.Context) {
	uid, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	listSessions(c, uid)
}

// GET /api/v1/me/claude-sessions/:conv
func MeClaudeSessionDetail(c *gin.Context) {
	uid, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	getSession(c, uid, c.Param("conv"))
}

// GET /api/v1/admin/claude-sessions   (super_admin only — see router.go's
// 2026-09-02 security-audit comment on why this moved out of the plain-admin
// group. listSessionsForAdmin/adminCanAccessSession, which used to give a
// plain role=admin caller narrower cross-user access, were removed as dead
// code: the route can no longer be reached by anything but super_admin, for
// whom "sub-scoped to role=user owners" was never the intended behavior —
// see listSessions(c, "") below, which reads every session unrestricted.)
func AdminClaudeSessions(c *gin.Context) {
	listSessions(c, "")
}

// GET /api/v1/admin/claude-sessions/:conv   (super_admin only)
func AdminClaudeSessionDetail(c *gin.Context) {
	getSession(c, "", c.Param("conv"))
}

// deleteSession removes a session, its turns, AND their S3-backed content.
// ownerSub != "" restricts to that owner.
//
// FIXED 2026-09-02: this used to delete only the ClaudeSession/
// ClaudeSessionTurn rows. When blobs live in S3 (BlobKey != "", the default
// in production — see blobstore.go), the actual recorded content —
// prompts, tool call args/results, file contents, model responses — was
// left permanently orphaned in the bucket, retrievable by anyone holding
// the shared object-storage credential, while the product told the user
// their data was deleted. Now fetches each turn's BlobKey before removing
// the DB rows and issues a real S3 DELETE for all three of its objects.
func deleteSession(c *gin.Context, ownerSub, convKey string) {
	var sess models.ClaudeSession
	if common.DB.Where("conv_key = ?", convKey).First(&sess).Error != nil {
		fail(c, http.StatusNotFound, 1404, "session not found")
		return
	}
	if ownerSub != "" && sess.UserSub != ownerSub {
		fail(c, http.StatusNotFound, 1404, "session not found")
		return
	}

	blobFailures := 0
	if common.Blobs != nil {
		var turns []models.ClaudeSessionTurn
		common.DB.Where("conv_key = ? AND blob_key != ''", convKey).Find(&turns)
		for _, t := range turns {
			blobFailures += deleteTurnBlobs(t.BlobKey)
		}
	}

	common.DB.Where("conv_key = ?", convKey).Delete(&models.ClaudeSessionTurn{})
	common.DB.Where("conv_key = ?", convKey).Delete(&models.ClaudeSession{})

	if blobFailures > 0 {
		// Still 200: the DB index is gone either way, and a stuck object is
		// not something the caller can retry their way out of from here — but
		// say so rather than a blanket "ok" that reads as a clean erasure.
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "session deleted; " +
			fmt.Sprintf("%d object(s) failed to delete from storage — see server logs", blobFailures)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok"})
}

// DELETE /api/v1/me/claude-sessions/:conv
func MeClaudeSessionDelete(c *gin.Context) {
	uid, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	deleteSession(c, uid, c.Param("conv"))
}

// DELETE /api/v1/admin/claude-sessions/:conv   (admin+)
func AdminClaudeSessionDelete(c *gin.Context) {
	deleteSession(c, "", c.Param("conv"))
}

// GET /api/v1/me/claude-recording
func MeClaudeRecordingGet(c *gin.Context) {
	uid, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"enabled": recordingEnabled(uid)}})
}

// POST /api/v1/me/claude-recording {enabled}
func MeClaudeRecordingSet(c *gin.Context) {
	uid, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		Enabled *bool `json:"enabled" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		fail(c, http.StatusBadRequest, 1400, "enabled (bool) required")
		return
	}
	// Upsert: a manual-PK Save() would UPDATE-only (no insert on first opt-out).
	pref := models.ClaudeRecordingPref{UserSub: uid, Enabled: *body.Enabled, UpdatedAt: time.Now().UTC()}
	if err := common.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_sub"}},
		DoUpdates: clause.AssignmentColumns([]string{"enabled", "updated_at"}),
	}).Create(&pref).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save pref: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"enabled": *body.Enabled}})
}

// ── per-field-box traffic breakdown ─────────────────────────────────────────

// fieldBoxRow is one row of the /code field-box panel.
type fieldBoxRow struct {
	// FieldBox "" means the turn was dispatched DIRECT from the cluster
	// (unlabelled account) — rendered as "(direct)".
	FieldBox string `json:"field_box"`
	// HomedUsers is how many users are ASSIGNED to this box right now — the
	// placement truth from claude_user_assignments (each field box holds one
	// pooled account), and the number a rebalance actually moves. This is what
	// "balance users, then load" is decided on.
	HomedUsers int64 `json:"homed_users"`
	// ActiveUsers is DISTINCT users whose turns egressed through this box in
	// the window. It is NOT placement: a lease rotation sends one user through
	// several boxes, so on live data this runs higher than HomedUsers and the
	// per-box values overlap heavily. Read it as "who touched this box", and
	// read HomedUsers for balance.
	ActiveUsers   int64     `json:"active_users"`
	Turns         int64     `json:"turns"`
	ViaRelay      int64     `json:"via_relay"`
	NotViaRelay   int64     `json:"not_via_relay"`
	RequestBytes  int64     `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
	InputTokens   int64     `json:"input_tokens"`
	OutputTokens  int64     `json:"output_tokens"`
	LastTs        time.Time `json:"last_ts"`
	// Fingerprint is the SDK User-Agent/X-Stainless-* fingerprint claude-proxy is
	// currently attaching to this box's egress — nil for the "" direct row and for
	// any homed-but-unconfigured label. See claude_field_fingerprint.go.
	//
	// gorm:"-" is required: fieldBoxRow is also a raw-SQL Scan target below, and
	// without it GORM's schema parser treats this pointer-to-struct field as an
	// association needing a foreign key, erroring the whole query ("invalid field
	// found for struct ... Fingerprint: define a valid foreign key for relations
	// or implement the Valuer/Scanner interface"). This field is only ever filled
	// by the Go loop after the Scan, never by SQL.
	Fingerprint *fieldFingerprintInfo `json:"fingerprint,omitempty" gorm:"-"`
}

// AdminClaudeFieldBoxes — GET /api/v1/admin/claude-field-boxes?hours=24
//
// Aggregates recorded turns by field box: traffic volume in TRUE wire bytes,
// plus the via_relay split. The split is the operational signal, not decoration:
// a box showing turns with not_via_relay > 0 means labelled accounts are being
// dispatched DIRECT from the cluster — the field-box path silently degraded and
// the egress IP is wrong. Nothing else surfaces that.
//
// Byte columns only cover turns recorded after the proxy started reporting them;
// older rows read 0 rather than being back-filled with a guess.
//
// Two user counts per box, and they answer different questions:
//   - homed_users  — users ASSIGNED to the box's account right now. Current
//     state, unaffected by the window. This is the balancing number.
//   - active_users — distinct users whose turns actually took the box in the
//     window. Traffic, not placement.
//
// They diverge by design: leases rotate, so one user's turns spread across
// several boxes and the active column overlaps between rows. active_users also
// undercounts — recording is per-user opt-out (ClaudeRecordingPref) and an
// opted-out user's turns are never written here, so they use the box invisibly.
// Treat active as a floor; treat homed as authoritative.
func AdminClaudeFieldBoxes(c *gin.Context) {
	hours := 24
	if v := strings.TrimSpace(c.Query("hours")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	// The user count needs the JOIN: turns carry the routing (field_box,
	// via_relay) but not the identity — user_sub lives on the session. Join is
	// LEFT so a turn whose session row is missing still counts toward traffic
	// instead of vanishing from the table; it just contributes no user.
	var rows []fieldBoxRow
	err := common.DB.Table("claude_session_turns AS t").
		Joins("LEFT JOIN claude_sessions AS s ON s.conv_key = t.conv_key").
		Select(`t.field_box                                    AS field_box,
		        COUNT(DISTINCT s.user_sub)                      AS active_users,
		        COUNT(*)                                        AS turns,
		        SUM(CASE WHEN t.via_relay THEN 1 ELSE 0 END)    AS via_relay,
		        SUM(CASE WHEN t.via_relay THEN 0 ELSE 1 END)    AS not_via_relay,
		        COALESCE(SUM(t.request_bytes),0)                AS request_bytes,
		        COALESCE(SUM(t.response_bytes),0)               AS response_bytes,
		        COALESCE(SUM(t.input_tokens),0)                 AS input_tokens,
		        COALESCE(SUM(t.output_tokens),0)                AS output_tokens,
		        MAX(t.ts)                                       AS last_ts`).
		Where("t.ts >= ?", since).
		Group("t.field_box").
		Order("response_bytes DESC").
		Scan(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "aggregate field boxes: "+err.Error())
		return
	}

	// via_relay only exists from the proxy build that started reporting it;
	// every turn before that defaults to FALSE in the column. Counting those as
	// degraded would report "we never measured this" as "this failed" — on the
	// live data that was 1622 phantom failures, enough to make the signal
	// useless. Derive the cutoff from the data itself (the first turn ever
	// observed relayed) rather than hardcoding a date, so it stays correct
	// across redeploys and backfills.
	var signalStart *time.Time
	var firstRelayed models.ClaudeSessionTurn
	if err := common.DB.Where("via_relay = ?", true).Order("ts ASC").First(&firstRelayed).Error; err == nil {
		signalStart = &firstRelayed.Ts
	}

	// Emit a ZERO row for every CONFIGURED field box the aggregation didn't
	// return. Without this the table lists only boxes that happened to carry
	// traffic in the window, so an idle box vanishes entirely — and a vanished
	// box is indistinguishable from a dead one. That is exactly backwards for a
	// health surface, and it bites hardest on short windows (the panel defaults
	// to 1h). Sourced from fieldRelays, the same map that actually does the
	// routing, so the roster can't drift from reality the way a hardcoded UI
	// list would.
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		seen[r.FieldBox] = true
	}
	for label := range fieldRelays {
		if !seen[label] {
			rows = append(rows, fieldBoxRow{FieldBox: label})
		}
	}

	// Homed users per box. Separate query on purpose: placement is CURRENT
	// state, not a property of the time window, so it must not be filtered by
	// `since` the way the traffic aggregate is. A box with zero turns in the
	// last hour still has its users homed on it, and that is exactly the case
	// where an operator is asking "who is on this box".
	//
	// The box label lives on the ACCOUNT (claude_quota_tokens.label). Now that
	// a user can belong to more than one ClaudePool (claude_user_assignments'
	// PK is (pool_id, user_sub), not just user_sub), the SAME user can have
	// multiple assignment rows that resolve to the same label — most likely
	// two unlabeled accounts, both COALESCE-ing to '' — so COUNT(DISTINCT
	// a.user_sub) is required here, not COUNT(*), or a multi-pool user is
	// counted once per pool they're homed in rather than once per person.
	var homed []struct {
		Label string
		N     int64
	}
	if err := common.DB.Table("claude_user_assignments AS a").
		Joins("LEFT JOIN claude_quota_tokens AS t ON t.email = a.account").
		Select("COALESCE(t.label,'') AS label, COUNT(DISTINCT a.user_sub) AS n").
		Group("t.label").
		Scan(&homed).Error; err == nil {
		idx := make(map[string]int, len(rows))
		for i, r := range rows {
			idx[r.FieldBox] = i
		}
		for _, h := range homed {
			if i, ok := idx[h.Label]; ok {
				rows[i].HomedUsers = h.N
				continue
			}
			// A box with users homed on it but no traffic in the window and no
			// relay entry. Surface it rather than dropping it — users homed on
			// a box that is not routing is precisely the misconfiguration this
			// panel exists to catch.
			rows = append(rows, fieldBoxRow{FieldBox: h.Label, HomedUsers: h.N})
			idx[h.Label] = len(rows) - 1
		}
	}

	// Fingerprint chip — only for rows backed by an actual configured relay
	// (fieldRelays), never the "" direct row and never a homed-but-unconfigured
	// label (claude-proxy has nothing to attach a fingerprint to there either).
	//
	// Prefer what claude-proxy REPORTS it is presenting over identity's own
	// re-derivation. The derivation is a mirror of the proxy's rotation logic
	// and is correct only while both copies stay byte-identical — which they
	// did not: it rendered `Anthropic/JS <sdk>` for a day after the proxy moved
	// to `claude-cli/<ver> (external, cli)`, and nothing caught it because each
	// side was self-consistent against its own copy. A reported row has exactly
	// one writer, so it can be stale but never invented.
	now := time.Now()
	reported := map[string]models.ClaudeFieldPresenting{}
	var presentRows []models.ClaudeFieldPresenting
	if err := common.DB.Find(&presentRows).Error; err == nil {
		for _, p := range presentRows {
			reported[p.Label] = p
		}
	}
	for i, r := range rows {
		if r.FieldBox == "" {
			continue
		}
		if _, ok := fieldRelays[r.FieldBox]; !ok {
			continue
		}
		if p, ok := reported[r.FieldBox]; ok && p.UserAgent != "" {
			at := p.UpdatedAt
			fp := fieldFingerprintInfo{
				UserAgent:      p.UserAgent,
				OS:             p.OS,
				Arch:           p.Arch,
				Runtime:        p.Runtime,
				PackageVersion: p.SDK,
				Override:       p.Source == "override",
				Reported:       true,
				ReportedAt:     &at,
			}
			rows[i].Fingerprint = &fp
			continue
		}
		// No report yet (proxy not yet upgraded, or this box has been idle
		// since the last identity restart). Fall back to the local derivation,
		// flagged so the panel can present it as a guess, not an observation.
		fp := fingerprintInfoForLabel(r.FieldBox, now)
		rows[i].Fingerprint = &fp
	}

	var totalReq, totalResp, totalTurns, totalDegraded int64
	for _, r := range rows {
		totalReq += r.RequestBytes
		totalResp += r.ResponseBytes
		totalTurns += r.Turns
	}
	// Distinct across the whole window, NOT the sum of the per-box counts — one
	// user can span several boxes (lease rotation moves them), so summing the
	// column would over-report the population. On live data the sum runs ~2.6x
	// the distinct total; the two disagreeing is normal, not a bug.
	var totalActive int64
	common.DB.Table("claude_session_turns AS t").
		Joins("JOIN claude_sessions AS s ON s.conv_key = t.conv_key").
		Where("t.ts >= ?", since).
		Distinct("s.user_sub").
		Count(&totalActive)
	// Homed totals DO sum: an assignment pins a user to exactly one account.
	var totalHomed int64
	for _, r := range rows {
		totalHomed += r.HomedUsers
	}
	// Degraded is counted with its own query so the per-row NotViaRelay stays a
	// raw fact while the ALERTABLE total is restricted to turns the signal
	// actually covers.
	if signalStart != nil {
		cut := *signalStart
		if cut.Before(since) {
			cut = since
		}
		common.DB.Model(&models.ClaudeSessionTurn{}).
			Where("ts >= ? AND field_box <> ? AND via_relay = ?", cut, "", false).
			Count(&totalDegraded)
	}
	ok(c, "ok", gin.H{
		"window_hours": hours,
		"boxes":        rows,
		"signal_since": signalStart,
		"totals": gin.H{
			// Users assigned across all boxes (sums cleanly), and distinct users
			// seen in the window (deliberately NOT the sum of the column).
			"homed_users":    totalHomed,
			"active_users":   totalActive,
			"turns":          totalTurns,
			"request_bytes":  totalReq,
			"response_bytes": totalResp,
			// Labelled turns that did NOT take the relay hop, across all boxes.
			// Non-zero = silent degradation somewhere; investigate before trusting
			// any egress claim.
			"degraded_turns": totalDegraded,
		},
	})
}
