package handler

// Run-as resolution for app actions that drive downstream services
// (FlowMesh, Lumilake/OaaS) on the user's behalf.
//
// Any lumid:form can carry these RESERVED keys — the platform consumes
// them before the action's own logic sees the values:
//
//   run_as_pat   — id of one of the USER's OWN PATs. Raw PAT values are
//                  hashed and unrecoverable, so identity mints a short-
//                  lived bridge JWT carrying that PAT's SCOPE PROFILE
//                  instead. Same principal — ownership of created
//                  resources stays with the user. "session" / "" = default.
//   run_as_key   — a pasted external key, used verbatim as the bearer
//                  (a genuinely different principal, e.g. a self-hosted
//                  fleet key). Wins over run_as_pat.
//   flowmesh_key — legacy alias for run_as_key (the GPU Rentals form
//                  shipped with it).
//
// Keys are deleted from `values` immediately — never logged, never
// echoed, never persisted. Returns ("", nil) when the caller should
// mint its own default (session) bearer.
//
// Grew out of the GPU Rentals 403 (2026-06-12): apps were implicitly
// deciding which credential they acted with. Any new action that
// submits FlowMesh or Lumilake work should call this first.

import (
	"fmt"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func runAsBearer(userID, email, role, audience string, values map[string]any) (string, error) {
	pasted := strings.TrimSpace(valStr(values, "run_as_key"))
	delete(values, "run_as_key")
	if legacy := strings.TrimSpace(valStr(values, "flowmesh_key")); pasted == "" && legacy != "" {
		pasted = legacy
	}
	delete(values, "flowmesh_key")
	patID := strings.TrimSpace(valStr(values, "run_as_pat"))
	delete(values, "run_as_pat")

	if pasted != "" {
		return pasted, nil
	}
	if patID == "" || patID == "session" {
		return "", nil // caller mints its default bridge JWT
	}
	var row models.Token
	if err := common.DB.Where("id = ? AND user_id = ?", patID, userID).First(&row).Error; err != nil {
		return "", fmt.Errorf("run-as token not found (it must be one of your own)")
	}
	now := time.Now()
	if row.RevokedAt != nil {
		return "", fmt.Errorf("run-as token %q is revoked", row.Name)
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
		return "", fmt.Errorf("run-as token %q is expired", row.Name)
	}
	scopes := common.ExpandFlowmeshScopes(strings.Fields(row.Scopes))
	bearer, _, _, err := common.IssueBridgeJWT(userID, email, role, audience, scopes, 10*time.Minute)
	if err != nil {
		return "", fmt.Errorf("mint run-as bearer: %w", err)
	}
	return bearer, nil
}
