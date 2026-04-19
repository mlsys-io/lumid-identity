package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"lumid_identity/internal/config"
)

// JWTClaims is the lum.id session JWT. Signed RS256 so downstream
// services can verify against our JWKS without round-tripping.
type JWTClaims struct {
	Scopes string `json:"scope,omitempty"` // space-separated, standard OAuth shape
	Email  string `json:"email,omitempty"`
	Role   string `json:"role,omitempty"`   // "user" | "admin"
	jwt.RegisteredClaims
}

// IssueJWT signs an access token for `userID`. Returns (token, jti, exp).
// jti goes into the sessions table for logout-everywhere.
func IssueJWT(userID, email, role string, scopes []string) (string, string, time.Time, error) {
	k := Keys.Active()
	if k == nil {
		return "", "", time.Time{}, fmt.Errorf("no active signing key")
	}
	jti, err := randID(16)
	if err != nil {
		return "", "", time.Time{}, err
	}
	ttl := time.Duration(config.G.JWT.AccessTTLSec) * time.Second
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	exp := now.Add(ttl)

	scope := ""
	for i, s := range scopes {
		if i > 0 {
			scope += " "
		}
		scope += s
	}

	claims := JWTClaims{
		Scopes: scope,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.G.App.Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{"lumid-ecosystem"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.Kid
	signed, err := token.SignedString(k.Private)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return signed, jti, exp, nil
}

// IssueIDToken signs an OIDC id_token whose `aud` is the requesting
// client_id (required by the spec, and verified by oauth2-proxy et al).
// Returns (token, exp).
func IssueIDToken(userID, email, name, clientID string, emailVerified bool) (string, time.Time, error) {
	k := Keys.Active()
	if k == nil {
		return "", time.Time{}, fmt.Errorf("no active signing key")
	}
	jti, err := randID(16)
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := time.Duration(config.G.JWT.AccessTTLSec) * time.Second
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	exp := now.Add(ttl)

	claims := jwt.MapClaims{
		"iss":            config.G.App.Issuer,
		"sub":            userID,
		"aud":            clientID,
		"exp":            exp.Unix(),
		"iat":            now.Unix(),
		"nbf":            now.Add(-30 * time.Second).Unix(),
		"jti":            jti,
		"email":          email,
		"email_verified": emailVerified,
		"name":           name,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = k.Kid
	signed, err := tok.SignedString(k.Private)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// VerifyJWT checks signature + expiry against our keyring. Downstream
// services that fetch JWKS use their own verify; this is for
// /oauth/introspect and /oauth/userinfo on our side.
func VerifyJWT(tokenStr string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("no kid")
		}
		k := Keys.ByKid(kid)
		if k == nil {
			return nil, fmt.Errorf("unknown kid %s", kid)
		}
		return k.Public, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func randID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
