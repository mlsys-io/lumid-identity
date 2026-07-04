// Fork / publish / propose — the Studio-side repo workflow (2026-06-11).
//
// xp.io has had fork + push + pulls APIs all along, but the only client
// was the operator CLI — Studio users had NO way to fork a showcase app,
// publish their changes, or propose them upstream. These three endpoints
// close that loop. Identity is the token authority, so it mints a
// short-lived user-scoped JWT (aud=xpcloud) and calls xpcloud AS the
// user — forks land under the caller's sub, never the operator's.
//
//	POST /me/apps/:app/fork     {name?}          → fork upstream repo +
//	                                               queue install of the fork
//	POST /me/apps/:app/publish  {summary?}       → queue app_push of the
//	                                               caller's tenant tree to
//	                                               their own repo
//	POST /me/apps/:app/propose  {title?, body?}  → open a pull request on
//	                                               the upstream (fork_of)
package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// xpcloudUserJWT mints a 15-minute JWT for the caller that xpcloud
// accepts via its introspect path. Scope is advisory (xpcloud keys
// everything off sub); the tight TTL bounds the blast radius.
func xpcloudUserJWT(userID string) (string, error) {
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err != nil {
		return "", fmt.Errorf("user not found")
	}
	tok, _, _, err := common.IssueBridgeJWT(u.ID, u.Email, u.Role, "xpcloud",
		[]string{"xpcloud:write"}, 15*time.Minute)
	return tok, err
}

func xpcloudJSON(method, url, bearer string, body any) (int, map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if out["detail"] == nil && len(raw) > 0 && len(out) == 0 {
		out["raw"] = string(raw[:min(len(raw), 300)])
	}
	return resp.StatusCode, out, nil
}

// appUpstreamSlug resolves the published repo an installed app came
// from. manifest.json's fork_of records the app's DEEP lineage, which
// can point at a long-gone source (mbb-ai's fork_of is a dead repo) —
// so only honor it when that repo still exists on xpcloud; otherwise
// fall back to the canonical showcase owner the user installed from.
func appUpstreamSlug(userID, app string) string {
	fallback := "a3f48236-ffe9-4fb9-9548-6e044d5cd9c7/" + app
	appDir := filepath.Join(tenantAppsDir(userID), app)
	mp, ok := ResolveManifestPath(appDir)
	if !ok {
		return fallback
	}
	b, err := os.ReadFile(mp)
	if err != nil {
		return fallback
	}
	var m struct {
		ForkOf string `json:"fork_of"`
	}
	if json.Unmarshal(b, &m) != nil || m.ForkOf == "" || !strings.Contains(m.ForkOf, "/") {
		return fallback
	}
	if code, _, err := xpcloudJSON(http.MethodGet,
		xpcloudBaseURL()+"/api/v1/repos/"+m.ForkOf, "", nil); err == nil && code == 200 {
		return m.ForkOf
	}
	return fallback
}

// MeAppFork — POST /me/apps/:app/fork
func MeAppFork(c *gin.Context) {
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
	var body struct {
		Name string `json:"name"`
	}
	_ = c.ShouldBindJSON(&body)
	newName := strings.TrimSpace(body.Name)
	if newName == "" {
		newName = app
	}
	if !slugRe.MatchString(newName) {
		fail(c, http.StatusBadRequest, 1400, "invalid fork name")
		return
	}
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint token: "+err.Error())
		return
	}
	upstream := appUpstreamSlug(userID, app)
	code, resp, err := xpcloudJSON(http.MethodPost,
		xpcloudBaseURL()+"/api/v1/repos/"+upstream+"/fork", bearer,
		map[string]any{"name": newName})
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "xpcloud: "+err.Error())
		return
	}
	if code >= 300 && code != http.StatusConflict {
		fail(c, http.StatusBadGateway, 1502,
			fmt.Sprintf("fork failed (%d): %v", code, resp["detail"]))
		return
	}
	// 409 = the fork already exists — converge: still (re)install it.
	// Install the fork into the caller's tenant so they can edit + run it.
	forkSlug := userID + "/" + newName
	intentID := writeIntentDirect(userID, "install", map[string]any{
		"slug": forkSlug, "as": newName, "bearer": bearer,
	})
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "fork created; installing",
		"data": gin.H{
			"fork":      forkSlug,
			"upstream":  upstream,
			"intent_id": intentID,
			"repo_url":  "https://xp.io/" + forkSlug,
		},
	})
}

// MeAppPublish — POST /me/apps/:app/publish
// Pushes the caller's tenant working tree of <app> to THEIR xp.io repo.
// Heavy lifting (bundle gather, semver, blob push) lives in Python
// sdk/ops.app_push — run by the lumid-scheduler intent picker with
// HOME=<tenant root> and the minted user bearer.
func MeAppPublish(c *gin.Context) {
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
	if st, err := os.Stat(filepath.Join(tenantAppsDir(userID), app)); err != nil || !st.IsDir() {
		fail(c, http.StatusNotFound, 1404, "app not installed in your account")
		return
	}
	var body struct {
		Summary string `json:"summary"`
	}
	_ = c.ShouldBindJSON(&body)
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint token: "+err.Error())
		return
	}
	intentID := writeIntentDirect(userID, "publish_app", map[string]any{
		"app": app, "summary": body.Summary, "bearer": bearer,
	})
	if intentID == "" {
		fail(c, http.StatusInternalServerError, 1500, "queue publish intent")
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "publish queued",
		"data": gin.H{
			"intent_id": intentID,
			"repo_url":  "https://xp.io/" + userID + "/" + app,
		},
	})
}

// MeAppPropose — POST /me/apps/:app/propose
// Opens a pull request on the upstream repo with the caller's published
// fork as head. The fork must be published first (publish endpoint).
func MeAppPropose(c *gin.Context) {
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
	var body struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	_ = c.ShouldBindJSON(&body)
	if strings.TrimSpace(body.Title) == "" {
		body.Title = "Changes from " + userID[:8] + "'s fork of " + app
	}
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint token: "+err.Error())
		return
	}
	// Upstream = the fork_of of the USER's repo (set by xpcloud at fork
	// time); fall back to the installed manifest's lineage.
	upstream := ""
	code, meta, err := xpcloudJSON(http.MethodGet,
		xpcloudBaseURL()+"/api/v1/repos/"+userID+"/"+app, bearer, nil)
	if err == nil && code == 200 {
		if fo, _ := meta["fork_of"].(string); fo != "" {
			upstream = fo
		}
	}
	if upstream == "" {
		upstream = appUpstreamSlug(userID, app)
	}
	code, resp, err := xpcloudJSON(http.MethodPost,
		xpcloudBaseURL()+"/api/v1/repos/"+upstream+"/pulls", bearer,
		map[string]any{
			"title":       body.Title,
			"body":        body.Body,
			"head_owner":  userID,
			"head_name":   app,
			"head_branch": "main",
			"base_branch": "main",
		})
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "xpcloud: "+err.Error())
		return
	}
	if code >= 300 {
		fail(c, http.StatusBadGateway, 1502,
			fmt.Sprintf("propose failed (%d): %v", code, resp["detail"]))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "pull request opened",
		"data": gin.H{
			"upstream":  upstream,
			"pull":      resp,
			"pulls_url": "https://xp.io/" + upstream + "/pulls",
		},
	})
}
