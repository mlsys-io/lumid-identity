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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const signalTailCap = 200

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
	appDir := resolveAppDir(userSub, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
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

	controlDir := filepath.Join(appDir, "data", "control")
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
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	records := readSignals(filepath.Join(appDir, "data", "control", "signals.jsonl"), loop)
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
