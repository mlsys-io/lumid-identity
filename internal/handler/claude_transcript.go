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
	"io"
	"net/http"
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
	UserSub      string          `json:"user_sub" binding:"required"`
	Account      string          `json:"account"`
	Endpoint     string          `json:"endpoint"`
	Stream       bool            `json:"stream"`
	InputTokens  int             `json:"input_tokens"`
	OutputTokens int             `json:"output_tokens"`
	DurationMs   int             `json:"duration_ms"`
	Truncated    bool            `json:"truncated"`
	Request      json.RawMessage `json:"request"`  // full request JSON
	Response     json.RawMessage `json:"response"` // full response (assembled JSON or raw SSE)
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
		RequestMetaGz: gzipBytes(metaJSON),
		NewMessagesGz: gzipBytes(deltaJSON),
		ResponseGz:    gzipBytes(body.Response),
		Truncated:     body.Truncated,
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
	if json.Unmarshal(response, &r) != nil {
		return 0
	}
	n := 0
	for _, b := range r.Content {
		if b.Type == "tool_use" {
			n++
		}
	}
	return n
}

// ── read paths ──────────────────────────────────────────────────────────────

type sessionCard struct {
	ConvKey      string    `json:"conv_key"`
	UserSub      string    `json:"user_sub,omitempty"`
	UserEmail    string    `json:"user_email,omitempty"`
	Account      string    `json:"account"`
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
			Account: s.Account, Model: s.Model,
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
	var turns []models.ClaudeSessionTurn
	common.DB.Where("conv_key = ?", convKey).Order("turn_index ASC").Find(&turns)

	type turnOut struct {
		TurnIndex    int             `json:"turn_index"`
		Ts           time.Time       `json:"ts"`
		Model        string          `json:"model"`
		Endpoint     string          `json:"endpoint"`
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
		out[i] = turnOut{
			TurnIndex: t.TurnIndex, Ts: t.Ts, Model: t.Model, Endpoint: t.Endpoint,
			Stream: t.Stream, InputTokens: t.InputTokens, OutputTokens: t.OutputTokens,
			ToolUseCount: t.ToolUseCount, DurationMs: t.DurationMs, Truncated: t.Truncated,
			RequestMeta: rawOrNull(gunzipBytes(t.RequestMetaGz)),
			NewMessages: rawOrNull(gunzipBytes(t.NewMessagesGz)),
			Response:    rawOrNull(gunzipBytes(t.ResponseGz)),
		}
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
		"data": gin.H{"session": sessionCard{
			ConvKey: sess.ConvKey, UserSub: sess.UserSub, Account: sess.Account,
			Model: sess.Model, Title: sess.Title, TurnCount: sess.TurnCount,
			InputTokens: sess.InputTokens, OutputTokens: sess.OutputTokens,
			ToolUseCount: sess.ToolUseCount, FirstTs: sess.FirstTs, LastTs: sess.LastTs,
		}, "turns": out}})
}

func rawOrNull(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
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

// GET /api/v1/admin/claude-sessions   (super_admin)
func AdminClaudeSessions(c *gin.Context) { listSessions(c, "") }

// GET /api/v1/admin/claude-sessions/:conv   (super_admin)
func AdminClaudeSessionDetail(c *gin.Context) { getSession(c, "", c.Param("conv")) }

// deleteSession removes a session and its turns. ownerSub != "" restricts to
// that owner.
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
	common.DB.Where("conv_key = ?", convKey).Delete(&models.ClaudeSessionTurn{})
	common.DB.Where("conv_key = ?", convKey).Delete(&models.ClaudeSession{})
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

// DELETE /api/v1/admin/claude-sessions/:conv   (super_admin)
func AdminClaudeSessionDelete(c *gin.Context) { deleteSession(c, "", c.Param("conv")) }

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
