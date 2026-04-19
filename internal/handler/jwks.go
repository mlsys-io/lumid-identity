package handler

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
)

// JWK describes a single RS256 public key in JWK form.
// https://datatracker.ietf.org/doc/html/rfc7517
type JWK struct {
	Kty string `json:"kty"` // RSA
	Use string `json:"use"` // sig
	Alg string `json:"alg"` // RS256
	Kid string `json:"kid"`
	N   string `json:"n"`   // modulus (base64url)
	E   string `json:"e"`   // exponent (base64url)
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GET /.well-known/jwks.json
//
// Every downstream service fetches + caches this to verify JWTs
// without a round-trip per request. We publish *all* keys (active +
// grace-period) so in-flight tokens from a just-rotated key still
// verify.
func Jwks(c *gin.Context) {
	var out JWKS
	for _, k := range common.Keys.All() {
		out.Keys = append(out.Keys, rsaToJWK(k.Kid, k.Public))
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, out)
}

// GET /.well-known/openid-configuration
func OpenIDConfig(c *gin.Context) {
	iss := config.G.App.Issuer
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth/authorize",
		"token_endpoint":                        iss + "/oauth/token",
		"userinfo_endpoint":                     iss + "/oauth/userinfo",
		"introspection_endpoint":                iss + "/oauth/introspect",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "password"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported": []string{
			"openid", "profile", "email",
			"quantarena:*", "runmesh:*", "flowmesh:*", "lumilake:*", "umami:*",
		},
	})
}

func rsaToJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
