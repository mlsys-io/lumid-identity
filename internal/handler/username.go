package handler

// Unified username (2026-11-28): ONE login name and ONE numeric uid per person on every cluster. The person picks
// the name on the Sandboxes page (GET/PUT /api/v1/user/username); sandbox-control and the per-machine host agent
// read GET /api/v1/admin/usernames and rename sandbox namespaces, host accounts and home folders to match.
// Changing it is allowed at any time; every change is kept in username_changes so sites can rename old -> new.

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// A POSIX login name every cluster accepts: lowercase, starts with a letter, 2-32 chars.
var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

// firstUID is where lum.id-assigned ids start: far above every hand-made host account (1000-1099 today) and the
// k8s/sandbox ranges, so a renumbered account can never collide with an existing local one.
const firstUID = 20000

// System and shared accounts nobody may take.
var baseReserved = []string{
	"root", "admin", "administrator", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
	"proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
	"messagebus", "sshd", "ubuntu", "debian", "docker", "flowmesh", "lumid", "gw", "sbx", "sandbox", "operator",
	"support", "postgres", "mysql", "redis", "minio", "git", "ci", "runner", "test", "guest", "user",
}

// reservedUsernames = base list + RESERVED_USERNAMES (comma-separated; the existing host logins not yet bound to a
// lum.id account, so a stranger cannot claim someone's login). An admin binds those with the admin endpoint.
func reservedUsernames() map[string]bool {
	m := map[string]bool{}
	for _, n := range baseReserved {
		m[n] = true
	}
	for _, n := range strings.Split(os.Getenv("RESERVED_USERNAMES"), ",") {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			m[n] = true
		}
	}
	return m
}

var (
	errUsernameInvalid  = errors.New("2-32 characters: lowercase letters, digits, - and _; must start with a letter")
	errUsernameReserved = errors.New("that name is reserved; ask an admin if it is your existing login")
	errUsernameTaken    = errors.New("that name is taken")
)

// checkUsername validates shape and reservation. allowReserved is for admins binding an existing host login.
func checkUsername(name string, allowReserved bool) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !usernameRe.MatchString(n) {
		return "", errUsernameInvalid
	}
	if !allowReserved && reservedUsernames()[n] {
		return "", errUsernameReserved
	}
	return n, nil
}

// suggestUsername derives a valid suggestion from an email local part ("Su.Zheng+x@..." -> "suzheng").
func suggestUsername(email string) string {
	local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
	local = strings.SplitN(local, "+", 2)[0]
	var b strings.Builder
	for _, r := range local {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	for len(s) > 0 && !(s[0] >= 'a' && s[0] <= 'z') {
		s = s[1:]
	}
	if len(s) > 32 {
		s = s[:32]
	}
	if len(s) < 2 || reservedUsernames()[s] {
		return "" // never suggest a name Save would refuse (e.g. "admin")
	}
	return s
}

// setUsername assigns name (and a uid on first set) to userID inside one transaction and records the change.
// An old name stays bound to its owner: nobody else may take a name another person held before.
func setUsername(userID, name, by string) (*models.User, error) {
	var out models.User
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		var u models.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).First(&u).Error; err != nil {
			return err
		}
		if u.Username != nil && *u.Username == name {
			out = u
			return nil
		}
		var n int64
		tx.Model(&models.User{}).Where("username = ? AND id <> ?", name, userID).Count(&n)
		if n > 0 {
			return errUsernameTaken
		}
		tx.Model(&models.UsernameChange{}).Where("(old_name = ? OR new_name = ?) AND user_id <> ?", name, name, userID).Count(&n)
		if n > 0 {
			return errUsernameTaken
		}
		old := ""
		if u.Username != nil {
			old = *u.Username
		}
		upd := map[string]interface{}{"username": name}
		if u.PosixUID == nil {
			var max struct{ M *int }
			tx.Model(&models.User{}).Select("MAX(posix_uid) AS m").Scan(&max)
			next := firstUID
			if max.M != nil && *max.M >= firstUID {
				next = *max.M + 1
			}
			upd["posix_uid"] = next
		}
		if err := tx.Model(&models.User{}).Where("id = ?", userID).Updates(upd).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				return errUsernameTaken
			}
			return err
		}
		if err := tx.Create(&models.UsernameChange{UserID: userID, OldName: old, NewName: name, By: by}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", userID).First(&out).Error
	})
	return &out, err
}

func usernameView(u *models.User) gin.H {
	var prev []string
	common.DB.Model(&models.UsernameChange{}).Where("user_id = ? AND old_name <> ''", u.ID).Order("id").Pluck("old_name", &prev)
	h := gin.H{"username": u.Username, "uid": u.PosixUID, "previous": prev}
	if u.Username == nil {
		h["suggested"] = suggestUsername(u.Email)
	}
	return h
}

// GET /api/v1/user/username — the caller's username, uid, earlier names, and a suggestion when none is set.
func UsernameGetHandler(c *gin.Context) {
	userID, ok := currentUserIDFor(c, common.SSHKeyReadAudiences...)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1004, "user not found")
		return
	}
	ok_(c, "ok", usernameView(&u))
}

// PUT /api/v1/user/username {"username": "..."} — choose or change your own username (identity audiences only).
func UsernameSetHandler(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1001, "username required")
		return
	}
	name, err := checkUsername(body.Username, false)
	if err != nil {
		fail(c, http.StatusBadRequest, 1001, err.Error())
		return
	}
	u, err := setUsername(userID, name, "")
	if errors.Is(err, errUsernameTaken) {
		fail(c, http.StatusConflict, 1009, err.Error())
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1000, "could not save the username")
		return
	}
	ok_(c, "ok", usernameView(u))
}

// GET /api/v1/admin/usernames — every person with a username: what sandbox-control and the host agents apply.
func AdminUsernamesListHandler(c *gin.Context) {
	var users []models.User
	common.DB.Where("username IS NOT NULL").Order("posix_uid").Find(&users)
	var changes []models.UsernameChange
	common.DB.Order("id").Find(&changes)
	prev := map[string][]string{}
	for _, ch := range changes {
		if ch.OldName != "" {
			prev[ch.UserID] = append(prev[ch.UserID], ch.OldName)
		}
	}
	out := make([]gin.H, 0, len(users))
	for _, u := range users {
		out = append(out, gin.H{"id": u.ID, "email": u.Email, "username": u.Username, "uid": u.PosixUID,
			"previous": prev[u.ID], "status": u.Status})
	}
	ok_(c, "ok", gin.H{"users": out, "total": len(out)})
}

// PUT /api/v1/admin/users/:id/username {"username": "...", "allow_reserved": true} — an admin binds an existing
// host login (reserved names allowed) or fixes a name.
func AdminUsernameSetHandler(c *gin.Context) {
	adminID, _ := currentUserID(c)
	var body struct {
		Username      string `json:"username"`
		AllowReserved bool   `json:"allow_reserved"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1001, "username required")
		return
	}
	name, err := checkUsername(body.Username, body.AllowReserved)
	if err != nil {
		fail(c, http.StatusBadRequest, 1001, err.Error())
		return
	}
	u, err := setUsername(c.Param("id"), name, adminID)
	if errors.Is(err, errUsernameTaken) {
		fail(c, http.StatusConflict, 1009, err.Error())
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, http.StatusNotFound, 1004, "user not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1000, "could not save the username")
		return
	}
	ok_(c, "ok", usernameView(u))
}
