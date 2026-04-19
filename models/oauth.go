package models

import "time"

// OAuthClient is a downstream app that can request tokens via OIDC.
// Seeded with: market, runmesh, umami, flowmesh, lumilake, lumid-cli.
type OAuthClient struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ClientID      string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"client_id"`
	SecretHash    string    `gorm:"type:varchar(255)" json:"-"` // bcrypt; empty for public clients (PKCE-only)
	Name          string    `gorm:"type:varchar(128);not null" json:"name"`
	RedirectURIs  string    `gorm:"type:text;not null" json:"-"` // newline-separated
	GrantTypes    string    `gorm:"type:varchar(255);not null" json:"-"` // authorization_code refresh_token etc.
	AllowedScopes string    `gorm:"type:text;not null" json:"-"` // space-separated
	IsPublic      bool      `gorm:"default:false" json:"is_public"`
	CreatedAt     time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

// OAuthCode is the short-lived authorization_code grant.
// PKCE is required — code_challenge + code_challenge_method must be
// present and match the token request's code_verifier.
type OAuthCode struct {
	Code                string    `gorm:"type:varchar(64);primaryKey" json:"code"`
	ClientID            string    `gorm:"type:varchar(64);index;not null" json:"client_id"`
	UserID              string    `gorm:"type:varchar(36);index;not null" json:"user_id"`
	RedirectURI         string    `gorm:"type:varchar(512);not null" json:"redirect_uri"`
	Scopes              string    `gorm:"type:text" json:"scopes"`
	CodeChallenge       string    `gorm:"type:varchar(128)" json:"code_challenge"`
	CodeChallengeMethod string    `gorm:"type:varchar(16)" json:"code_challenge_method"` // S256
	ExpiresAt           time.Time `gorm:"not null;index" json:"expires_at"`
	UsedAt              *time.Time `json:"used_at,omitempty"`
	CreatedAt           time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (OAuthCode) TableName() string { return "oauth_codes" }

// Session is a JWT reference — primary purpose is logout-everywhere.
// The JWT itself is stateless; when a user hits logout we mark the
// matching session revoked and every verify path checks this.
type Session struct {
	ID        string     `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID    string     `gorm:"type:varchar(36);index;not null" json:"user_id"`
	JTI       string     `gorm:"type:varchar(64);uniqueIndex;not null" json:"jti"`
	ClientID  string     `gorm:"type:varchar(64);index" json:"client_id"`
	UserAgent string     `gorm:"type:varchar(255)" json:"user_agent,omitempty"`
	IP        string     `gorm:"type:varchar(45)" json:"ip,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (Session) TableName() string { return "sessions" }

// SigningKey holds the RS256 keypair. Public part is published via
// JWKS; private part signs JWTs. Rotation: new key inserted, marked
// active; old key stays available for verify until its grace period
// ends (default 48h past RotatedAt).
type SigningKey struct {
	Kid        string    `gorm:"type:varchar(32);primaryKey" json:"kid"`
	Alg        string    `gorm:"type:varchar(16);default:'RS256'" json:"alg"`
	PrivatePEM string    `gorm:"type:text;not null" json:"-"`
	PublicJWK  string    `gorm:"type:text;not null" json:"public_jwk"`
	Active     bool      `gorm:"default:true;index" json:"active"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (SigningKey) TableName() string { return "signing_keys" }
