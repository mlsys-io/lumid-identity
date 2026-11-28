package handler

// Claim an existing host login (2026-11-28). People who already log in to our machines as, say, "junyi" cannot pick
// that name on the Sandboxes page: it is in RESERVED_USERNAMES so a stranger cannot take it. A claim lets the owner
// take it themselves by proving control of the login:
//
//  1. POST /api/v1/user/username/claim {"login":"junyi"} returns a one-time code and the command
//     `echo <code> > ~/.lumid-claim`, to be run on any machine where they log in as junyi.
//  2. The per-host verifier (deploy_infra k8s-lift/host-users/claim-verify.sh, an admin credential, root-only)
//     lists pending claims, reads ~/.lumid-claim of each login that exists on that host (a regular file owned by
//     the login, never through a symlink) and POSTs the code to /api/v1/admin/username-claims/:id/verify.
//  3. On a match the login becomes the person's username through setUsername, exactly like an admin bind.
//
// Only the SHA-256 of the code is stored, and the code is returned only by the create call. Being able to write a
// file owned by the login inside its home folder is the proof.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	claimTTL         = 24 * time.Hour
	claimFile        = "~/.lumid-claim"
	claimPending     = "pending"
	claimVerified    = "verified"
	claimExpired     = "expired"
	claimRejected    = "rejected"
	claimCodePrefix  = "lc_"
	claimCodeRandLen = 16 // bytes -> 32 hex chars; the whole code is 35 bytes, well under the verifier's 64-byte cap
)

var (
	errClaimNotHostLogin = errors.New("that is not one of the existing logins on our machines; pick a new username instead")
	errClaimBound        = errors.New("that login is already someone's username")
	errClaimYours        = errors.New("that login is already your username")
)

// A hostname as the verifier reports it: a DNS label-ish name, at most 64 chars.
var claimHostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// hostLogins is the RESERVED_USERNAMES list alone: the existing host logins not yet bound to a lum.id account.
func hostLogins() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("RESERVED_USERNAMES"), ",") {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			m[n] = true
		}
	}
	return m
}

// checkClaimLogin: the login must have a valid shape, be one of the existing host logins, and not be a system or
// shared account (root, ubuntu, … stay unclaimable even if someone listed them as host logins).
func checkClaimLogin(login string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(login))
	if !usernameRe.MatchString(n) {
		return "", errUsernameInvalid
	}
	for _, b := range baseReserved {
		if n == b {
			return "", errClaimNotHostLogin
		}
	}
	if !hostLogins()[n] {
		return "", errClaimNotHostLogin
	}
	return n, nil
}

// boundRefusal decides from what the DB knows about a login whether userID may claim it: boundTo is the id of the
// user whose username it is ("" = nobody); heldByOther = it appears in someone else's username history.
func boundRefusal(userID, boundTo string, heldByOther bool) error {
	switch {
	case boundTo == userID:
		return errClaimYours
	case boundTo != "" || heldByOther:
		return errClaimBound
	}
	return nil
}

func loginBoundRefusal(userID, login string) error {
	var u models.User
	boundTo := ""
	if err := common.DB.Select("id").Where("username = ?", login).Limit(1).Find(&u).Error; err == nil {
		boundTo = u.ID
	}
	var n int64
	common.DB.Model(&models.UsernameChange{}).Where("(old_name = ? OR new_name = ?) AND user_id <> ?", login, login, userID).Count(&n)
	return boundRefusal(userID, boundTo, n > 0)
}

func hashClaimCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

// claimCodeMatches compares SHA-256(code) with the stored hash in constant time.
func claimCodeMatches(code, storedHash string) bool {
	got := hashClaimCode(code)
	return len(storedHash) == len(got) && subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

func newClaimCode() (string, error) {
	b := make([]byte, claimCodeRandLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return claimCodePrefix + hex.EncodeToString(b), nil
}

func claimExpiresAt(cl *models.UsernameClaim) time.Time { return cl.CreatedAt.Add(claimTTL) }

// claimStatusAt is the status a claim has at `now`: a pending claim past its 24 h reads as expired.
func claimStatusAt(cl *models.UsernameClaim, now time.Time) string {
	if cl.Status == claimPending && !now.Before(claimExpiresAt(cl)) {
		return claimExpired
	}
	return cl.Status
}

// expireStale marks every pending claim older than claimTTL expired (cheap; the table is tiny).
func expireStale(now time.Time) {
	common.DB.Model(&models.UsernameClaim{}).
		Where("status = ? AND created_at <= ?", claimPending, now.Add(-claimTTL)).
		Update("status", claimExpired)
}

// claimView is what the person sees: never the code, never the hash.
func claimView(cl *models.UsernameClaim, now time.Time) gin.H {
	h := gin.H{"id": cl.ID, "login": cl.Login, "status": claimStatusAt(cl, now),
		"created_at": cl.CreatedAt, "expires_at": claimExpiresAt(cl)}
	if cl.Host != "" {
		h["host"] = cl.Host
	}
	if cl.VerifiedAt != nil {
		h["verified_at"] = cl.VerifiedAt
	}
	return h
}

// POST /api/v1/user/username/claim {"login":"junyi"} — start a claim; returns the code ONCE.
func UsernameClaimCreateHandler(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var body struct {
		Login string `json:"login"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1001, "login required")
		return
	}
	login, err := checkClaimLogin(body.Login)
	if err != nil {
		fail(c, http.StatusBadRequest, 1001, err.Error())
		return
	}
	if err := loginBoundRefusal(userID, login); err != nil {
		fail(c, http.StatusConflict, 1009, err.Error())
		return
	}
	code, err := newClaimCode()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1000, "could not start the claim")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	cl := models.UsernameClaim{UserID: userID, Login: login, CodeHash: hashClaimCode(code), Status: claimPending, CreatedAt: now}
	// One pending claim per person: a new request replaces the old one.
	common.DB.Model(&models.UsernameClaim{}).Where("user_id = ? AND status = ?", userID, claimPending).Update("status", claimRejected)
	if err := common.DB.Create(&cl).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1000, "could not start the claim")
		return
	}
	ok_(c, "ok", gin.H{"id": cl.ID, "login": cl.Login, "code": code,
		"command": "echo " + code + " > " + claimFile, "expires_at": claimExpiresAt(&cl)})
}

// GET /api/v1/user/username/claim — the caller's latest claim (status only, never the code); data is null if none.
func UsernameClaimGetHandler(c *gin.Context) {
	userID, ok := currentUserIDFor(c, common.SSHKeyReadAudiences...)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var cl models.UsernameClaim
	if err := common.DB.Where("user_id = ?", userID).Order("id DESC").Limit(1).Find(&cl).Error; err != nil || cl.ID == 0 {
		ok_(c, "ok", nil)
		return
	}
	ok_(c, "ok", claimView(&cl, time.Now()))
}

// GET /api/v1/admin/username-claims?status=pending — what the host verifiers work through. No codes, no hashes.
// status: pending (default) | verified | expired | rejected | all.
func AdminUsernameClaimsListHandler(c *gin.Context) {
	now := time.Now()
	expireStale(now)
	status := strings.ToLower(strings.TrimSpace(c.DefaultQuery("status", claimPending)))
	q := common.DB.Model(&models.UsernameClaim{}).Order("id")
	switch status {
	case claimPending, claimVerified, claimExpired, claimRejected:
		q = q.Where("status = ?", status)
	case "all":
	default:
		fail(c, http.StatusBadRequest, 1001, "status must be pending, verified, expired, rejected or all")
		return
	}
	var claims []models.UsernameClaim
	q.Limit(1000).Find(&claims)
	emails := map[string]string{}
	if len(claims) > 0 {
		ids := make([]string, 0, len(claims))
		for _, cl := range claims {
			ids = append(ids, cl.UserID)
		}
		var users []models.User
		common.DB.Select("id", "email").Where("id IN ?", ids).Find(&users)
		for _, u := range users {
			emails[u.ID] = u.Email
		}
	}
	out := make([]gin.H, 0, len(claims))
	for i := range claims {
		cl := &claims[i]
		h := claimView(cl, now)
		h["user_id"] = cl.UserID
		h["email"] = emails[cl.UserID]
		out = append(out, h)
	}
	ok_(c, "ok", gin.H{"claims": out, "total": len(out)})
}

// POST /api/v1/admin/username-claims/:id/verify {"host":"luyao0","code":"<read from ~login/.lumid-claim>"}
// 200 = bound; 409 = wrong code (claim stays pending) or not pending / login taken meanwhile; 410 = expired.
func AdminUsernameClaimVerifyHandler(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, 1001, "bad claim id")
		return
	}
	var body struct {
		Host string `json:"host"`
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		fail(c, http.StatusBadRequest, 1001, "host and code required")
		return
	}
	host := strings.TrimSpace(body.Host)
	if !claimHostRe.MatchString(host) {
		fail(c, http.StatusBadRequest, 1001, "host must be a hostname (letters, digits, . _ -; at most 64)")
		return
	}
	var cl models.UsernameClaim
	if err := common.DB.Where("id = ?", id).Limit(1).Find(&cl).Error; err != nil || cl.ID == 0 {
		fail(c, http.StatusNotFound, 1004, "claim not found")
		return
	}
	now := time.Now()
	switch claimStatusAt(&cl, now) {
	case claimPending:
	case claimExpired:
		common.DB.Model(&models.UsernameClaim{}).Where("id = ? AND status = ?", cl.ID, claimPending).Update("status", claimExpired)
		fail(c, http.StatusGone, 1010, "claim expired")
		return
	default:
		fail(c, http.StatusConflict, 1009, "claim is "+cl.Status+", not pending")
		return
	}
	if !claimCodeMatches(body.Code, cl.CodeHash) {
		fail(c, http.StatusConflict, 1009, "code does not match")
		return
	}
	if _, err := setUsername(cl.UserID, cl.Login, "claim:"+host); err != nil {
		if errors.Is(err, errUsernameTaken) {
			common.DB.Model(&models.UsernameClaim{}).Where("id = ? AND status = ?", cl.ID, claimPending).Update("status", claimRejected)
			fail(c, http.StatusConflict, 1009, errClaimBound.Error())
			return
		}
		fail(c, http.StatusInternalServerError, 1000, "could not save the username")
		return
	}
	at := now.UTC().Truncate(time.Second)
	common.DB.Model(&models.UsernameClaim{}).Where("id = ? AND status = ?", cl.ID, claimPending).
		Updates(map[string]interface{}{"status": claimVerified, "host": host, "verified_at": at})
	// Anyone else waiting on the same login lost it; stop the verifiers retrying their claims.
	common.DB.Model(&models.UsernameClaim{}).Where("login = ? AND status = ? AND id <> ?", cl.Login, claimPending, cl.ID).
		Update("status", claimRejected)
	cl.Status, cl.Host, cl.VerifiedAt = claimVerified, host, &at
	h := claimView(&cl, now)
	h["user_id"] = cl.UserID
	ok_(c, "ok", h)
}
