package handler

// Staging a slate of candidate experiments, and serving it back.
//
// The producer is an app's `propose_experiments annotate` verb: it takes what a
// fan-out of planners proposed, checks each candidate against the ways an
// experiment declaration can run and record nothing, and emits the slate with a
// verdict per candidate. This file is where that slate becomes readable by the
// app's Proposals surface.
//
// WHY NOT AN INTENT. An intent moves work TO the scheduler. The problem here is
// the opposite — getting data BACK from wherever the verb ran. Identity mounts
// no tenant volume (its only volumeMount is signing-keys), so a slate the
// scheduler wrote to its own PVC is unreadable here, and the panel would stay
// empty forever. MeAppExperiment, MeAppRun and MeAppSpec each hit this wall and
// each answered the same way: the producer self-reports, identity serves MySQL.
//
// TWO WRITE PATHS, because there are two kinds of producer:
//
//   POST /api/v1/internal/app-proposals   X-Bridge-Secret, carries user_sub.
//       For the scheduler / a cycle, which has the bridge secret and is acting
//       on a tenant's behalf. Mirrors InternalAppExperimentRecord.
//
//   POST /api/v1/me/apps/:app/proposals   PAT or session, user from the token.
//       For a caller that IS the user — notably a chatbox turn, whose sandbox
//       holds a per-turn LUMID_PAT. This is the path that closes the loop from
//       chat, and the reason it exists: plan mode is read-only and the sandbox's
//       MCP runs in `safe` mode, so a planning turn cannot write into a bundle
//       at all. It can, however, hand the slate to its own account.

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// proposalSlateMaxBytes caps a stored slate.
//
// A slate is bounded by construction — a handful of candidates, each with its
// findings — so anything past this is a caller sending something else. Chosen
// to match artifactMaxContent rather than invented: both are "one blob a human
// will read", and having two different answers to that question is how limits
// drift apart.
const proposalSlateMaxBytes = 256 * 1024

type appProposalBody struct {
	UserSub string         `json:"user_sub"` // bridge path only; ignored on /me
	App     string         `json:"app"`
	Slate   map[string]any `json:"slate"`
}

// saveProposalSlate is the shared sink for both write paths.
//
// Supersedes rather than accumulates: one row per (user, app). The file reader
// already takes the newest slate and ignores older ones, so keeping history
// here would create a second, disagreeing notion of "current".
func saveProposalSlate(userSub, app string, slate map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(slate)
	if err != nil {
		return nil, err
	}
	if len(raw) > proposalSlateMaxBytes {
		return nil, errSlateTooLarge
	}
	num := func(k string) int {
		if v, ok := slate[k].(float64); ok {
			return int(v)
		}
		return 0
	}
	var ts int64
	if v, ok := slate["ts"].(float64); ok {
		ts = int64(v)
	}
	row := models.MeAppProposal{
		UserSub: userSub, App: app,
		Slate:   string(raw),
		SlateTs: ts,
		// Reported by the producer, never recomputed here.
		N:               num("n"),
		WillCollect:     num("will_collect"),
		WillBeInvisible: num("will_be_invisible"),
	}
	res := common.DB.Where("user_sub = ? AND app = ?", userSub, app).
		Assign(row).FirstOrCreate(&models.MeAppProposal{})
	if res.Error != nil {
		return nil, res.Error
	}
	return gin.H{
		"app": app, "slate_ts": ts, "n": row.N,
		"will_collect": row.WillCollect, "will_be_invisible": row.WillBeInvisible,
	}, nil
}

type slateTooLarge struct{}

func (slateTooLarge) Error() string { return "slate too large" }

var errSlateTooLarge = slateTooLarge{}

// InternalAppProposalRecord — POST /api/v1/internal/app-proposals
//
// Bridge-authenticated machine path. Mirrors InternalAppExperimentRecord,
// including taking user_sub from the body: the caller is the scheduler acting
// for a tenant, not the tenant.
func InternalAppProposalRecord(c *gin.Context) {
	var b appProposalBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if b.UserSub == "" || b.App == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub and app required")
		return
	}
	if !slugRe.MatchString(b.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if b.Slate == nil {
		fail(c, http.StatusBadRequest, 1400, "slate required")
		return
	}
	out, err := saveProposalSlate(b.UserSub, b.App, b.Slate)
	if err == errSlateTooLarge {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "slate too large")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "recorded", "data": out})
}

// MeAppProposalsStage — POST /me/apps/:app/proposals
//
// The user's own path. The slate is stored against the CALLER's sub, taken from
// the token and never from the body: a chatbox turn holds a per-turn PAT, and
// letting it name a user_sub would let one tenant stage into another's panel.
func MeAppProposalsStage(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	// Bound ONCE into a generic map: gin consumes the body, so this cannot be
	// re-read into a second struct. Accept either {"slate": {...}} or the
	// verb's output posted bare, because the natural thing for a producer to
	// do is pipe what it already printed.
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	slate, _ := body["slate"].(map[string]any)
	if slate == nil && body["proposals"] != nil {
		slate = body
	}
	if slate == nil {
		fail(c, http.StatusBadRequest, 1400, "slate required (or post the annotate output directly)")
		return
	}
	out, err := saveProposalSlate(userID, app, slate)
	if err == errSlateTooLarge {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "slate too large")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "staged", "data": out})
}

// storedProposalSlate returns the self-reported slate for one app, or nil.
//
// DISK WINS when it has a slate, for the same reason it does for experiment
// state: an operator-shared app runs in the daemon's own HOME, so identity can
// read that file directly and it is the freshest copy. The DB is the fallback
// for everything identity cannot see — which is every tenant install.
func storedProposalSlate(userSub, app string) map[string]any {
	var row models.MeAppProposal
	q := common.DB.Where("user_sub = ? AND app = ?", userSub, app).First(&row)
	if q.Error != nil || row.Slate == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(row.Slate), &out); err != nil {
		return nil
	}
	return out
}
