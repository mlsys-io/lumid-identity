package handler

// The installed spec, crossing the node boundary.
//
// resolveAppDir's cross-node fallback materialises an app's PUBLISHED bundle,
// because that is the only copy a cloud identity pod can reach. Every read
// surface then describes the published app: its loops, its datasets, its UI —
// and its experiments. For an app that is installed and then EDITED, that is the
// wrong app. define_experiment and experiment_control edit the install, through
// the scheduler, and publish nothing; so a freshly defined experiment existed on
// the scheduler's volume and nowhere identity could see it, and no amount of
// waiting made it appear (chiquanji@gmail.com, 2026-09-16).
//
// The scheduler already echoes the installed spec after install/update
// (_echo_app_spec) to /internal/app-spec. That route did not exist — the echo
// had been POSTing into a 404 since the handler it was written against was
// removed. This is that route, plus the store behind it.
//
// Best-effort by design, on both ends: a failed echo must never fail the write
// it followed, and a missing row must never fail a read. The published copy
// remains the fallback, which is exactly what it was always meant to be.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type appSpecBody struct {
	UserSub  string            `json:"user_sub"`
	App      string            `json:"app"`
	SpecYAML string            `json:"spec_yaml"`
	UIFiles  map[string]string `json:"ui_files"`
}

// InternalAppSpecRecord — POST /api/v1/internal/app-spec (X-Bridge-Secret).
func InternalAppSpecRecord(c *gin.Context) {
	var b appSpecBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if b.UserSub == "" || b.App == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub and app required")
		return
	}
	// AN EMPTY SPEC IS NOT AN UPDATE. A read that failed on the scheduler's side
	// would otherwise blank the stored copy and silently demote every reader
	// back to the published bundle — the precise failure this store exists to
	// end, reintroduced as a write.
	if b.SpecYAML == "" {
		fail(c, http.StatusBadRequest, 1400, "spec_yaml is empty; refusing to blank the stored spec")
		return
	}
	ui := "{}"
	if len(b.UIFiles) > 0 {
		if raw, err := json.Marshal(b.UIFiles); err == nil {
			ui = string(raw)
		}
	}
	row := models.MeAppSpec{
		UserSub: b.UserSub, App: b.App,
		SpecYAML: b.SpecYAML, UIFiles: ui,
		UpdatedAt: time.Now(),
	}
	res := common.DB.Where("user_sub = ? AND app = ?", b.UserSub, b.App).
		Assign(row).FirstOrCreate(&models.MeAppSpec{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+res.Error.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "recorded",
		"data": gin.H{"app": b.App, "bytes": len(b.SpecYAML), "ui_files": len(b.UIFiles)}})
}

// storedAppSpec returns the self-reported spec for one installed app, or nil.
func storedAppSpec(userSub, app string) *models.MeAppSpec {
	if userSub == "" || app == "" || common.DB == nil {
		return nil
	}
	var row models.MeAppSpec
	if err := common.DB.Where("user_sub = ? AND app = ?", userSub, app).
		First(&row).Error; err != nil || row.SpecYAML == "" {
		return nil
	}
	return &row
}
