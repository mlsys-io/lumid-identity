package models

import "gorm.io/gorm"

// AllTables is every table we own. AutoMigrate iterates this on
// startup. Order doesn't matter for GORM but we group by domain.
var AllTables = []interface{}{
	&User{},
	&Identity{},
	&Token{},
	&AuditLog{},
	&OAuthClient{},
	&OAuthCode{},
	&Session{},
	&SigningKey{},
	&InvitationCode{},
	&PasswordReset{},
	&SSHKey{},
	&UserAccessGrant{},
	&ClaudeUserAssignment{},
	&GoogleGrant{},
	&AppSecret{},
	&UsageEvent{},
	&PowerAutomateToken{},
	&MicrosoftGrant{},
	&MicrosoftGrantPending{},
	&GpuRental{},
	&MeAppIntent{},
	&MeAppRun{},
	&MeArtifact{},
	&ClaudeQuotaToken{},
	&ClaudeSessionBinding{},
	&ClaudeQuotaSnapshot{},
	&ClaudeSession{},
	&ClaudeSessionTurn{},
	&ClaudeRecordingPref{},
	&MePref{},
	&ClaudePoolWindow{},
	&ClaudeFingerprintObservation{},
	&ClaudeFieldPresenting{},
	&MeChat{},
	&MeDraft{},
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(AllTables...)
}
