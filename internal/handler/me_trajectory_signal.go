package handler

// Control-signal channel for the Studio trajectory view.
//
//   POST /me/apps/:app/trajectory/signal   — issue a control signal (e.g. a
//                                             right-click "branch from here").
//   GET  /me/apps/:app/trajectory/signals  — list signals (optionally ?loop=).
//
// Signals are appended to <appDir>/data/control/signals.jsonl (one JSON record
// per line). This is a durable, append-only channel an operator/loop can drain
// later; the handlers here only record + read. Read-only except the single
// append-write; best-effort, never panics.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const signalTailCap = 200

// ── cross-node signal store (DB) ─────────────────────────────────────────────
//
// On UKS the append-only <appDir>/data/control/signals.jsonl lives on the
// SCHEDULER pod's PVC, which identity can't mount — POST used to 404 (WS-5).
// When the bundle isn't on this pod's disk, signals land in me_docs (the same
// replica-safe store as chats/personas), one doc per record. NOTE: the loop's
// proposer stage still drains the PVC file — mirroring DB signals down to the
// scheduler is the remaining half of the cross-node tenant-app-files gap.

// meDocKindSignal — MeDoc kind for cross-node control signals.
const meDocKindSignal = "app_signal"

// signalDocKeep — per-user cap across apps (tail semantics like the file log).
const signalDocKeep = 500

// signalDoc is the me_docs payload for one signal record.
type signalDoc struct {
	App string       `json:"app"`
	Rec signalRecord `json:"rec"`
}

// signalDocsForApp returns the caller's DB signals for one app, oldest→newest
// (append order, like the file), filtered by loop, capped at signalTailCap.
func signalDocsForApp(userSub, app, loop string) []signalRecord {
	rows, err := meDocList(userSub, meDocKindSignal)
	if err != nil {
		return []signalRecord{}
	}
	out := []signalRecord{}
	for _, r := range rows {
		var d signalDoc
		if json.Unmarshal([]byte(r.Doc), &d) != nil || d.App != app {
			continue
		}
		if loop != "" && d.Rec.Loop != "" && d.Rec.Loop != loop {
			continue
		}
		out = append(out, d.Rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ts < out[j].Ts })
	if len(out) > signalTailCap {
		out = out[len(out)-signalTailCap:]
	}
	return out
}

// countPendingSignalDocs counts the caller's DB signals with status=="pending"
// for one app (0 on any error) — the cross-node twin of countPendingSignals.
func countPendingSignalDocs(userSub, app string) int {
	n := 0
	for _, rec := range signalDocsForApp(userSub, app, "") {
		if rec.Status == "pending" {
			n++
		}
	}
	return n
}

// signalRecord is one line in signals.jsonl.
type signalRecord struct {
	Ts            string         `json:"ts"`
	Action        string         `json:"action"`
	Loop          string         `json:"loop,omitempty"`
	FromID        string         `json:"from_id,omitempty"`
	FromVariantID string         `json:"from_variant_id,omitempty"`
	Config        map[string]any `json:"config,omitempty"`
	Note          string         `json:"note,omitempty"`
	By            string         `json:"by"`
	Status        string         `json:"status"`
}

type signalReq struct {
	Loop          string         `json:"loop"`
	Action        string         `json:"action"`
	FromID        string         `json:"from_id"`
	FromVariantID string         `json:"from_variant_id"`
	Config        map[string]any `json:"config"`
	Note          string         `json:"note"`
}

// MeTrajectorySignal — POST /me/apps/:app/trajectory/signal
func MeTrajectorySignal(c *gin.Context) {
	userSub, ok2 := currentUserID(c)
	if !ok2 {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	var req signalReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	req.Action = strings.TrimSpace(req.Action)
	if req.Action == "" {
		fail(c, http.StatusBadRequest, 1400, "action required")
		return
	}
	if req.Loop != "" && !slugRe.MatchString(req.Loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	rec := signalRecord{
		Ts:            time.Now().UTC().Format(time.RFC3339),
		Action:        req.Action,
		Loop:          req.Loop,
		FromID:        req.FromID,
		FromVariantID: req.FromVariantID,
		Config:        req.Config,
		Note:          req.Note,
		By:            userSub,
		Status:        "pending",
	}

	appDir := resolveAppDir(userSub, app)
	if appDir == "" {
		// Cross-node: the control dir lives on the scheduler PVC. Record the
		// signal in the DB store instead of 404ing (WS-5). A bogus app name
		// still 404s — the caller's published repo is the existence proxy.
		if _, okSpec := fetchRepoSpecYAML(userSub, app); !okSpec {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		doc, err := json.Marshal(signalDoc{App: app, Rec: rec})
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not encode signal")
			return
		}
		if err := meDocSave(userSub, meDocKindSignal, uuid.New().String(), string(doc)); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not record signal")
			return
		}
		go meDocPrune(userSub, meDocKindSignal, signalDocKeep)
		ok(c, "recorded", gin.H{
			"recorded": rec,
			"pending":  countPendingSignalDocs(userSub, app),
		})
		return
	}

	controlDir, err := ResolveRuntimeWritePath(appDir, "data/control")
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "could not prepare control dir")
		return
	}
	if err := os.MkdirAll(controlDir, 0o775); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "could not prepare control dir")
		return
	}
	path := filepath.Join(controlDir, "signals.jsonl")
	line, err := json.Marshal(rec)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "could not encode signal")
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "could not open signals log")
		return
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		fail(c, http.StatusInternalServerError, 1500, "could not write signal")
		return
	}
	f.Close()

	ok(c, "recorded", gin.H{
		"recorded": rec,
		"pending":  countPendingSignals(path),
	})
}

// MeTrajectorySignals — GET /me/apps/:app/trajectory/signals?loop=
func MeTrajectorySignals(c *gin.Context) {
	userSub, ok2 := currentUserID(c)
	if !ok2 {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Query("loop")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	appDir := resolveAppDir(userSub, app)
	if appDir == "" {
		// Cross-node: the PVC file is unreachable — list the DB-recorded
		// signals instead (same shape; empty when none exist).
		records := signalDocsForApp(userSub, app, loop)
		ok(c, "ok", gin.H{"signals": records, "count": len(records)})
		return
	}

	controlDir, _ := ResolveRuntimeReadPath(appDir, "data/control")
	records := readSignals(filepath.Join(controlDir, "signals.jsonl"), loop)
	ok(c, "ok", gin.H{"signals": records, "count": len(records)})
}

// readSignals returns the last ~signalTailCap records, filtered by loop when
// non-empty (a record with empty loop matches any). Missing file → empty list.
func readSignals(path, loop string) []signalRecord {
	out := []signalRecord{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec signalRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if loop != "" && rec.Loop != "" && rec.Loop != loop {
			continue
		}
		out = append(out, rec)
	}
	if len(out) > signalTailCap {
		out = out[len(out)-signalTailCap:]
	}
	return out
}

// countPendingSignals counts records with status=="pending" (0 on any error).
func countPendingSignals(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec signalRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Status == "pending" {
			n++
		}
	}
	return n
}
