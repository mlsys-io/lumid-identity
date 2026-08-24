package models

import "time"

// InvitationRedemption records that a specific user redeemed a specific code.
//
// WHY THIS EXISTS
// Redemption used to be bounded by `users.invitation_code_used` — one code per
// user, ever. That is the right rule for a SIGNUP code and the wrong rule for a
// code that carries access grants, and the two had been conflated. Every one of
// the twenty cohort accounts already had `invitation_code_used` set from
// signup, so a scoped code minted for them was refused with 409 before it could
// grant anything: the feature worked only for brand-new accounts, which is the
// opposite of who needed it.
//
// Simply relaxing that guard is not safe on its own. Without a per-(user, code)
// record, one user could replay the same code repeatedly and drain a 20-use
// seat allocation by themselves — the uses_remaining decrement is per redeem,
// not per person. This table is what makes "you may redeem another code, but
// not this one twice" expressible.
//
// The unique index is the enforcement, not the SELECT that precedes it: two
// concurrent redeems of the same code by the same user both pass the check and
// one must lose at the database. Treat a duplicate-key error on insert as
// "already redeemed", not as a server error.
type InvitationRedemption struct {
	ID     string `gorm:"type:varchar(36);primaryKey"                              json:"id"`
	UserID string `gorm:"type:varchar(36);index;not null;uniqueIndex:uk_user_code,priority:1" json:"user_id"`
	Code   string `gorm:"type:varchar(64);index;not null;uniqueIndex:uk_user_code,priority:2" json:"code"`

	// What the code granted at the time it was redeemed. Denormalised on
	// purpose: the code's own `scopes` can be edited or the row deleted later,
	// and "what access did this person actually receive, and when" has to stay
	// answerable from the redemption itself.
	Scopes string `gorm:"type:varchar(512)" json:"scopes,omitempty"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"redeemed_at"`
}

func (InvitationRedemption) TableName() string { return "invitation_redemptions" }
