package handler

import (
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Durable use counts for superseded names (models.DeprecatedUse): the evidence
// VERBS.md stage 3 ("remove after two releases with zero use") waits on.
//
//	GET /api/v1/admin/deprecations?days=N    super_admin; default 30 days
//
// Recording is fire-and-forget: a counter must never slow or fail the call it
// counts. A failed write is logged, and the [deprecated-route] log line still
// fires, so a DB outage loses counts, not requests.

// recordDeprecatedUse adds one to today's count for (surface, name).
func recordDeprecatedUse(surface, name, by string) {
	db := common.DB
	if db == nil {
		return
	}
	now := time.Now().UTC()
	go func() {
		err := db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "surface"}, {Name: "name"}, {Name: "day"}},
			DoUpdates: clause.Assignments(map[string]any{
				"count": gorm.Expr("`count` + 1"), "last_at": now, "last_by": by,
			}),
		}).Create(&models.DeprecatedUse{
			Surface: surface, Name: name, Day: now.Format("2006-01-02"), Count: 1, LastAt: now, LastBy: by,
		}).Error
		if err != nil {
			log.Printf("[deprecated-use] count write failed for %s %s: %v", surface, name, err)
		}
	}()
}

// noteModelToolName counts a chat tool the model called by a superseded name.
// Call it with the name exactly as the model sent it, before resolution:
// canonical names resolve TO the old ones, so counting after resolution would
// count every canonical call as a use of the name it replaced.
func noteModelToolName(name, userID string) {
	if _, superseded := supersededChatTools[name]; superseded {
		recordDeprecatedUse("chat_tool", name, userID)
	}
}

type deprecationRow struct {
	Surface   string    `json:"surface"`
	Name      string    `json:"name"`
	Successor string    `json:"successor,omitempty"`
	Total     int64     `json:"total"`
	Days      int       `json:"days_used"`
	LastAt    time.Time `json:"last_at,omitempty"`
	LastBy    string    `json:"last_by,omitempty"`
}

// AdminDeprecations — GET /admin/deprecations. Superseded chat tools with no
// row are listed with total 0; a route appears once it has been called, since
// the route table does not say which routes carry deprecatedRoute.
func AdminDeprecations(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days < 1 || days > 365 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days+1).Format("2006-01-02")
	var uses []models.DeprecatedUse
	if err := common.DB.Where("day >= ?", since).Find(&uses).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read deprecated uses: "+err.Error())
		return
	}
	var first models.DeprecatedUse
	trackingSince := ""
	if common.DB.Order("day asc").Limit(1).Find(&first).RowsAffected > 0 {
		trackingSince = first.Day
	}
	rows := map[string]*deprecationRow{}
	for old, successor := range supersededChatTools {
		rows["chat_tool\x00"+old] = &deprecationRow{Surface: "chat_tool", Name: old, Successor: successor}
	}
	for _, u := range uses {
		k := u.Surface + "\x00" + u.Name
		r := rows[k]
		if r == nil {
			r = &deprecationRow{Surface: u.Surface, Name: u.Name}
			rows[k] = r
		}
		r.Total += u.Count
		r.Days++
		if u.LastAt.After(r.LastAt) {
			r.LastAt, r.LastBy = u.LastAt, u.LastBy
		}
	}
	out := make([]*deprecationRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Surface+out[i].Name < out[j].Surface+out[j].Name
	})
	ok(c, "ok", gin.H{"window_days": days, "since": since, "tracking_since": trackingSince, "names": out})
}
