package handler

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /admin/oauth-clients — super_admin only. Lists every OAuth client
// (services that federate against lum.id). Used by the super-admin
// dashboard to show "what's wired into our auth right now". Secrets
// never leave the DB; only the bcrypt hash exists, and we don't return
// even that.

type oauthClientRow struct {
	ClientID      string    `json:"client_id"`
	Name          string    `json:"name"`
	IsPublic      bool      `json:"is_public"`
	GrantTypes    []string  `json:"grant_types"`
	AllowedScopes []string  `json:"allowed_scopes"`
	RedirectURIs  []string  `json:"redirect_uris"`
	CreatedAt     time.Time `json:"created_at"`
}

func AdminOAuthClientsList(c *gin.Context) {
	var rows []models.OAuthClient
	common.DB.Order("created_at ASC").Find(&rows)

	out := make([]oauthClientRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, oauthClientRow{
			ClientID:      r.ClientID,
			Name:          r.Name,
			IsPublic:      r.IsPublic,
			GrantTypes:    splitNonEmpty(r.GrantTypes, " "),
			AllowedScopes: splitNonEmpty(r.AllowedScopes, " "),
			RedirectURIs:  splitNonEmpty(r.RedirectURIs, "\n"),
			CreatedAt:     r.CreatedAt,
		})
	}

	ok(c, "ok", gin.H{"clients": out, "total": len(out)})
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
