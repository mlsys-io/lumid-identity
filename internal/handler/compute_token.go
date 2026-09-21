package handler

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Per-user `lumilake:jobs:write` PAT for loops whose BODY is a compute DAG.
//
// WHY THIS EXISTS. `sdk/apps/compute.py::resolve_token` accepts a credential by
// SHAPE — only `lm_pat_live_*` / `rm_pat_live_*`. Under a chat- or UI-triggered
// run the picker sets `LUMID_PAT` to the caller's LOGIN JWT
// (`aud=lumid-ecosystem`), which it refuses on purpose. So a loop declaring
// `engine: {type: lumilake}` runs fine on a SCHEDULE — the scheduler holds a
// real PAT — and fails from the two surfaces that are the actual product.
//
// ROLE DOES NOT SUBSTITUTE FOR SCOPE HERE. Measured 2026-09-21: `admin.pat`,
// whose account is super_admin, was itself refused by Lumilake at preview with
//
//	403 kind-level write on job requires 'lumilake:jobs:write'
//
// while a demo PAT carrying that scope passed. Lumilake checks the token's
// scopes in its own permission layer, independently of lum.id's role gates, so
// the credential genuinely has to carry the scope. Handing the run a
// super_admin PAT would therefore be both over-privileged AND still wrong.
//
// GATED ON THE MANIFEST, NOT AN APP LIST — and that is the whole point.
// `lqt_strategy_pat.go` gates on a hardcoded slug set, and records what that
// cost: the app was renamed `lqt-mailbox` → `quant-research`, the gate silently
// stopped matching, and 83% of all deploy rejections on the live mailbox were
// that one gate missing its app. A compute engine is DECLARED in the spec, so
// this asks the spec. A new app that declares one is served with no edit here,
// which is the generalization property the estate is short of.
//
// The shape — mint short-lived per user, cache encrypted, inject as env — is
// deliberately identical to `lqt_strategy_pat.go`. Read that file's comments
// before changing this one; every one of them was paid for.

const (
	// Long enough for a queued intent to be claimed and run — a cold model load
	// on the fleet has been measured at 20m44s for a single row — and short
	// enough that a leaked token is near-worthless. Matches the lqt:strategy
	// TTL rather than inventing a second number.
	computePATTTL = 2 * time.Hour

	// The ONLY scope. Not `lumilake:admin`: a run needs to submit a job, and
	// nothing here should be able to administer the fleet.
	computeScope = "lumilake:jobs:write"

	// Cached under the app the token is for, so a user running two
	// compute-bearing apps does not have one app's cache answer for the other.
	computePATCacheKey = "__lumilake_compute_pat_cache"

	// Re-mint once the cached token is within this of expiry, so a cycle never
	// receives a credential that dies mid-run. A fleet job can run for tens of
	// minutes, so this is generous on purpose.
	computePATRenewBefore = 25 * time.Minute
)

// computeEngineTypes — engine types whose runtime submits to a compute service
// and therefore needs a scoped token.
//
// `flowmesh` is NOT here. It is declared-but-unimplemented: LumidOS #102 makes
// `gate_workflow_contract` reject it at publish, and the runtime refuses it at
// dispatch. Minting a credential for a path that cannot run would hand out a
// live token for nothing.
var computeEngineTypes = map[string]bool{
	"lumilake": true,
}

// appDeclaresComputeEngine reports whether any loop in this app's spec declares
// a compute engine.
//
// Reads the MATERIALISED TENANT COPY rather than fetching the blob over HTTP.
// `InternalAppSecretsFetch` runs per cycle per user, so a network round-trip
// here is on the hot path for every cycle of every app — including the large
// majority that declare no compute engine at all and would pay it for a
// guaranteed "no".
//
// A miss returns false, which fails CLOSED: the app then fails at compute.py's
// own credential check, whose message names the cause ("no PAT-shaped
// credential found ... A chat-triggered run receives the caller's login JWT,
// which this service will reject"). That is a worse run but an honest one, and
// strictly better than this layer minting a credential it could not justify.
func appDeclaresComputeEngine(userSub, app string) bool {
	app = strings.TrimSpace(app)
	if userSub == "" || app == "" {
		return false
	}
	dir := tenantCacheDir(userSub, app)
	var spec []byte
	for _, name := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && len(b) > 0 {
			spec = b
			break
		}
	}
	if spec == nil {
		return false
	}
	return specDeclaresComputeEngine(spec)
}

// specDeclaresComputeEngine is the pure half, so the decision is testable
// without a filesystem or a DB. The owner-resolution bug in me_app_cache.go was
// a wrong DECISION rather than a wrong query, and a test needing MySQL is a
// test that skips in CI — which is how that assumption survived a green suite.
func specDeclaresComputeEngine(spec []byte) bool {
	var doc struct {
		// `workflows:` is the canonical synonym for `loops:` (W1.1); both are
		// accepted by the runtime, so both are read here or an app using the
		// newer spelling would silently get no credential.
		Loops     []rawComputeLoop `yaml:"loops"`
		Workflows []rawComputeLoop `yaml:"workflows"`
	}
	if yaml.Unmarshal(spec, &doc) != nil {
		return false
	}
	for _, l := range append(append([]rawComputeLoop{}, doc.Loops...), doc.Workflows...) {
		if computeEngineTypes[strings.TrimSpace(l.Engine.Type)] {
			return true
		}
	}
	return false
}

type rawComputeLoop struct {
	Engine struct {
		Type string `yaml:"type"`
	} `yaml:"engine"`
}

// mintComputePAT returns a fresh scoped PAT for userSub, or "" if minting
// fails. Best-effort BY DESIGN: a miss must not block the run.
func mintComputePAT(userSub string) string {
	exp := time.Now().Add(computePATTTL)
	tok, _, err := mintPATForUser(
		userSub,
		"lumilake-compute (intent, auto)",
		[]string{computeScope},
		&exp,
		"intent",
	)
	if err != nil {
		log.Printf("[compute-pat] mint failed for %s: %v", userSub, err)
		return ""
	}
	return tok
}

// computePATCached returns a live compute PAT for userSub, minting one ONLY
// when there is no usable cached token.
//
// The caching is not an optimisation, it is the difference between one live
// credential per user and one per cycle. lqt_strategy_pat.go's first version
// minted on every call and produced 451 live deploy credentials for a cohort —
// 432 alive at once — before anyone noticed, because the write was both
// best-effort and silent. Hence: an EXPLICIT upsert (app_secrets has a
// composite PK, so `Save` silently no-ops after the first insert), and a logged
// reason on every miss.
func computePATCached(userSub, app string) string {
	miss := ""
	var row models.AppSecret
	if err := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userSub, app, computePATCacheKey).First(&row).Error; err == nil {
		if v, err := common.DecryptGrant(row.ValueEncrypted); err == nil {
			if exp, tok, ok := strings.Cut(v, ":"); ok && tok != "" {
				if unix, err := strconv.ParseInt(exp, 10, 64); err == nil {
					if time.Until(time.Unix(unix, 0)) > computePATRenewBefore {
						return tok
					}
					miss = fmt.Sprintf("expires too soon (in %s, need >%s)",
						time.Until(time.Unix(unix, 0)).Round(time.Second), computePATRenewBefore)
				} else {
					miss = "expiry not parseable: " + exp
				}
			} else {
				miss = "cached value has no <expiry>:<token> shape"
			}
		} else {
			miss = "decrypt failed: " + err.Error()
		}
	} else {
		miss = "no cache row: " + err.Error()
	}
	log.Printf("[compute-pat] cache MISS for %s/%s — %s (minting)", userSub, app, miss)

	tok := mintComputePAT(userSub)
	if tok == "" {
		return ""
	}
	enc, err := common.EncryptGrant(fmt.Sprintf("%d:%s", time.Now().Add(computePATTTL).Unix(), tok))
	if err == nil {
		if err := common.DB.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "user_sub"}, {Name: "app_slug"}, {Name: "key"},
			},
			DoUpdates: clause.AssignmentColumns([]string{"value_encrypted", "updated_at"}),
		}).Create(&models.AppSecret{
			UserSub: userSub, AppSlug: app,
			Key: computePATCacheKey, ValueEncrypted: enc,
		}).Error; err != nil {
			log.Printf("[compute-pat] cache WRITE failed for %s/%s: %v "+
				"(next cycle will mint again)", userSub, app, err)
		}
	}
	return tok
}
