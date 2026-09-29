package handler

import (
	"strings"
	"time"

	"gorm.io/gorm"

	"lumid_identity/models"
)

// invitationCodeError is a validation failure the caller should surface as a
// 400 with a UI-presentable message, as opposed to an unexpected DB error.
type invitationCodeError struct{ msg string }

func (e *invitationCodeError) Error() string { return e.msg }

// consumeInvitationCodeTx validates rawCode and, if it is currently usable,
// atomically consumes one use — all inside tx.
//
// This is the enforcement RegisterHandler was missing: it used to accept ANY
// non-empty string as an invitation code (see CVE note on RegisterHandler),
// so the browser's "field is non-empty" check was the entire invite gate.
//
// The bounded-code decrement mirrors RedeemInvitationCodeHandler's pattern —
// a conditional `UPDATE ... WHERE uses_remaining > 0` with the decrement done
// server-side via gorm.Expr, not a read-then-write in Go — so two concurrent
// signups racing on the last seat of a max_uses code cannot both win. tx MUST
// be the same transaction that goes on to create the consuming row (the new
// user), so a rollback anywhere downstream also returns the seat.
func consumeInvitationCodeTx(tx *gorm.DB, rawCode string) (*models.InvitationCode, error) {
	code := strings.TrimSpace(rawCode)
	if code == "" {
		return nil, &invitationCodeError{"invitation_code required"}
	}

	var inv models.InvitationCode
	if err := tx.Where("code = ?", code).First(&inv).Error; err != nil {
		return nil, &invitationCodeError{"invitation code invalid"}
	}
	if inv.RevokedAt != nil {
		return nil, &invitationCodeError{"invitation code revoked"}
	}
	if inv.ExpiresAt != nil && inv.ExpiresAt.Before(time.Now()) {
		return nil, &invitationCodeError{"invitation code expired"}
	}
	// max_uses == 0 means unlimited; otherwise uses_remaining must be > 0.
	if inv.MaxUses != 0 && inv.UsesRemaining <= 0 {
		return nil, &invitationCodeError{"invitation code exhausted"}
	}

	now := time.Now()
	if inv.MaxUses != 0 {
		res := tx.Model(&models.InvitationCode{}).
			Where("code = ? AND uses_remaining > 0", code).
			Updates(map[string]any{
				"uses_remaining": gorm.Expr("uses_remaining - 1"),
				"last_used_at":   &now,
			})
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 0 {
			// A concurrent claimer took the last seat between our SELECT and
			// this UPDATE.
			return nil, &invitationCodeError{"invitation code exhausted"}
		}
		inv.UsesRemaining--
	} else if err := tx.Model(&models.InvitationCode{}).
		Where("code = ?", code).
		Update("last_used_at", &now).Error; err != nil {
		return nil, err
	}
	inv.LastUsedAt = &now
	return &inv, nil
}
