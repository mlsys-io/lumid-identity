package common

import (
	"errors"
	"os"
	"strings"
	"sync"
)

// AudienceEcosystem is the platform-general audience. Session JWTs (the
// lm_session cookie), OAuth access tokens and tenant bearers carry it, and
// every Lumid service accepts it. Anything ELSE in `aud` names one service.
const AudienceEcosystem = "lumid-ecosystem"

// IdentityAudiences are the audiences lum.id's OWN API accepts (PATs, admin,
// session-bearer, Google grants, OAuth authorize, /me). Besides the general
// session audience:
//   - "lumid-identity": claude-proxy's per-user forward to this service
//     (k8s-lift/claude-proxy/app/gateway.go, forward(..., "lumid-identity", ...)).
//   - "lumid": the internal-mint recipe used to act as a service account
//     (deploy_infra k8s-lift/flowmesh-vast/SERVICE_ACCOUNT.md, step 3).
//
// A token minted for FlowMesh, Runmesh, LQT, Lumilake, lum.id/data, xpcloud,
// or an OIDC id_token minted for a client (aud = client_id), is NOT accepted
// here: until 2026-11-25 any of them could call the admin surface, mint fresh
// bridge tokens via /session-bearer, mint PATs, or read the user's Google
// access token, because every check was signature-only.
var IdentityAudiences = []string{AudienceEcosystem, "lumid-identity", "lumid"}

// ErrAudience is returned when a JWT verifies but was minted for another
// service.
var ErrAudience = errors.New("token audience not accepted here")

// AudienceAllowed reports whether any of the token's audiences is in accepted.
func AudienceAllowed(c *JWTClaims, accepted ...string) bool {
	if c == nil {
		return false
	}
	for _, a := range c.Audience {
		for _, want := range accepted {
			if a == want {
				return true
			}
		}
	}
	return false
}

// VerifyJWTFor verifies the signature (VerifyJWT) and then requires one of
// the accepted audiences.
func VerifyJWTFor(tok string, accepted ...string) (*JWTClaims, error) {
	c, err := VerifyJWT(tok)
	if err != nil {
		return nil, err
	}
	if !AudienceAllowed(c, accepted...) {
		return nil, ErrAudience
	}
	return c, nil
}

// VerifyIdentityJWT is VerifyJWTFor with IdentityAudiences — use it for every
// check that authenticates a caller to lum.id's own API.
func VerifyIdentityJWT(tok string) (*JWTClaims, error) {
	return VerifyJWTFor(tok, IdentityAudiences...)
}

// ---- introspection policy ------------------------------------------------

// defaultUnboundAudiences are the service audiences /oauth/introspect still
// accepts from a caller that does NOT say which service it is (no `audience`
// parameter). They are exactly the bridge audiences live consumers receive
// today, measured 2026-11-25:
//
//	flowmesh, runmesh          session-bearer (lumid-bridge-*, ~90 mints/14d each)
//	lumilake                   lum.id/data job dispatch (jobs/dispatch.rs)
//	lumid-data, xpcloud,
//	lumid-identity             claude-proxy gateway forwards
//	lqt                        session-bearer aud=lqt (lqt-auth verifies via JWKS,
//	                           but its PAT fallback introspects)
//	claude-proxy               the opsagent claude_proxy/messages-stream probe
//	                           (LQT tools/opsagent/stack_check.py), which claude-proxy
//	                           introspects
//
// It is a migration allowance, not a policy: a consumer that passes
// `audience=<its name>` is strict immediately, and once every consumer does,
// set INTROSPECT_UNBOUND_AUDIENCES="" (empty = none) to make unbound callers
// accept only lumid-ecosystem. OIDC id_tokens (aud = a client_id such as
// harbor, argocd, runmesh-broker) and any other audience are refused for
// unbound callers from day one.
var defaultUnboundAudiences = []string{
	"flowmesh", "runmesh", "lumilake", "lumid-data", "xpcloud", "lumid-identity", "lqt",
	"claude-proxy",
}

var (
	unboundOnce sync.Once
	unboundAuds map[string]bool
)

// UnboundIntrospectAudiences returns the allowance set, from
// INTROSPECT_UNBOUND_AUDIENCES (comma-separated; set-but-empty means none)
// or the default.
func UnboundIntrospectAudiences() map[string]bool {
	unboundOnce.Do(func() {
		list := defaultUnboundAudiences
		if v, ok := os.LookupEnv("INTROSPECT_UNBOUND_AUDIENCES"); ok {
			list = nil
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					list = append(list, p)
				}
			}
		}
		unboundAuds = make(map[string]bool, len(list))
		for _, a := range list {
			unboundAuds[a] = true
		}
	})
	return unboundAuds
}

// IntrospectAudienceVerdict decides whether a verified JWT is valid for the
// introspecting caller.
//
//   - want != "": the caller named its service. Accept the general audience
//     or exactly `want`. Nothing else — this is the strict, target mode.
//   - want == "": accept the general audience, or one in the unbound
//     allowance (unbound=true tells the caller to log it for migration).
func IntrospectAudienceVerdict(c *JWTClaims, want string) (ok bool, unbound bool) {
	if AudienceAllowed(c, AudienceEcosystem) {
		return true, false
	}
	if want != "" {
		return AudienceAllowed(c, want), false
	}
	allow := UnboundIntrospectAudiences()
	for _, a := range c.Audience {
		if allow[a] {
			return true, true
		}
	}
	return false, false
}

// ResetUnboundIntrospectAudiencesForTest makes the next call re-read the env.
// Tests only.
func ResetUnboundIntrospectAudiencesForTest() { resetUnboundForTest() }

func resetUnboundForTest() {
	unboundOnce = sync.Once{}
	unboundAuds = nil
}
