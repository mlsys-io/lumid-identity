package handler

// Multiple Claude account pools — CRUD, migration/backfill, and lease-time
// pool resolution.
//
// Splits the single shared Claude account pool into named ClaudePools, each
// with its own accounts (ClaudeQuotaToken.PoolID, one-pool-per-account) and
// member users (ClaudePoolMember, many-to-many). See models/claude_pool.go
// for the full design rationale.
//
// Authorization: every endpoint here is plain RequireAdmin (router.go), the
// SAME level as account add/remove/drain. This codebase's actual precedent
// (verified in router.go) puts a destructive account op (DELETE
// /claude-token/:email) at the same gate as its reversible sibling (POST
// /claude-account/drain) specifically so the safe control is never harder to
// reach than the destructive one — the only things gated to RequireSuperAdmin
// here are ones that hand out BUDGET (reset-window) or expose per-user PII
// (session transcripts). Pool CRUD is neither.

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

var claudePoolIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

// validConservativeCeiling accepts the three-way sentinel conservativeCeiling
// (claude_balance_conservative.go) reads: positive = explicit value, 0 =
// inherit the global default, -1 = explicitly unlimited. Anything else
// (e.g. -5) has no defined meaning and is rejected rather than silently
// coerced.
func validConservativeCeiling(n int) bool { return n >= -1 }

// ── Migration / backfill ─────────────────────────────────────────────────

// claudePoolMigrationLock serialises the guarded DDL in EnsureDefaultClaudePool
// across replicas and across concurrent boots (2 identity pods run this on
// every restart). Without it, two pods can both observe
// primaryMarkerExists==0 / pkIsComposite==0 and race to run the same ALTER —
// the loser errors (duplicate column / PK conflict) and log.Fatalf
// crash-loops the pod, exactly the class of bug fixed once already in commit
// ff8ba60 for the same PK-widen operation. A 30s wait is generous for
// one-time DDL that normally completes in milliseconds once the schema is
// already current.
const claudePoolMigrationLock = "claude_pool_migration"

// EnsureDefaultClaudePool seeds the "default" pool and backfills every
// pre-existing account/user into it, idempotently. Called once from
// cmd/identity/main.go right after models.AutoMigrate on EVERY pod boot —
// this service is fully self-deploying (git tag -> CI -> Argo Image Updater
// rolls it automatically) with no operator migration step, so the backfill
// must be idempotent Go code, not a numbered migrations/*.sql file an
// operator would need to run by hand (see migrations/010_claude_pools.sql,
// kept only as a documentation copy of what this function does).
//
// Every step is IF-NOT-EXISTS / INSERT-IGNORE, so this is a no-op on every
// boot after the first, and safe to run concurrently across replicas.

func EnsureDefaultClaudePool(db *gorm.DB) error {
	const defaultID = models.DefaultClaudePoolID

	var locked int
	if err := db.Raw("SELECT GET_LOCK(?, 30)", claudePoolMigrationLock).Scan(&locked).Error; err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if locked != 1 {
		return fmt.Errorf("could not acquire migration lock %q within 30s — another pod may be stuck mid-migration", claudePoolMigrationLock)
	}
	defer db.Exec("DO RELEASE_LOCK(?)", claudePoolMigrationLock)

	// 1. Resolve admin@lum.id's sub for OwnerSub. A missing admin@lum.id row
	// degrades to an empty owner + a loud warning rather than failing
	// startup — pool ownership is attribution-only, never load-bearing for
	// access control (see models/claude_pool.go).
	var ownerSub string
	if err := db.Raw(`SELECT id FROM users WHERE email = 'admin@lum.id' LIMIT 1`).
		Scan(&ownerSub).Error; err != nil {
		log.Printf("claude-pool: lookup admin@lum.id for default pool ownership failed: %v", err)
	}
	if ownerSub == "" {
		log.Printf("claude-pool: admin@lum.id not found — seeding default pool with no owner_sub (attribution only, does not block anything)")
	}
	// created_at/updated_at set explicitly: this raw INSERT bypasses GORM's
	// Create() hooks (autoCreateTime/autoUpdateTime), which only fire for
	// pools made through AdminClaudePoolCreate. Without this the seeded
	// "default" pool's timestamps read NULL forever — caught live (not by
	// any unit test, since those all go through GORM's Create) when the
	// admin API returned "0001-01-01T00:00:00Z" for it.
	if err := db.Exec(`
		INSERT IGNORE INTO claude_pools (id, name, mode, owner_sub, conservative_ceiling, created_at, updated_at)
		VALUES (?, 'Default Pool', ?, ?, 0, NOW(3), NOW(3))`,
		defaultID, models.ClaudePoolModeDistributed, ownerSub).Error; err != nil {
		return fmt.Errorf("seed default pool: %w", err)
	}
	// Self-heal a "default" pool seeded by the version of this function that
	// omitted created_at/updated_at (shipped briefly before this fix) —
	// idempotent no-op once healed.
	if err := db.Exec(`UPDATE claude_pools SET created_at = NOW(3), updated_at = NOW(3)
		WHERE id = ? AND created_at IS NULL`, defaultID).Error; err != nil {
		return fmt.Errorf("backfill default pool timestamps: %w", err)
	}

	// 2. claude_pool_members: generated-column + partial-unique-index DDL.
	// GORM's AutoMigrate creates the table (plain columns, from AllTables)
	// but cannot express a generated column or a partial-unique index, so
	// that part is raw SQL here, guarded so it only ever runs once.
	var primaryMarkerExists int64
	db.Raw(`SELECT COUNT(*) FROM information_schema.COLUMNS
	         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'claude_pool_members'
	           AND COLUMN_NAME = 'primary_marker'`).Scan(&primaryMarkerExists)
	if primaryMarkerExists == 0 {
		if err := db.Exec(`
			ALTER TABLE claude_pool_members
			  ADD COLUMN primary_marker VARCHAR(36) AS (IF(is_primary, user_sub, NULL)) STORED,
			  ADD UNIQUE KEY uq_cpm_one_primary (primary_marker)`).Error; err != nil {
			return fmt.Errorf("add claude_pool_members primary_marker: %w", err)
		}
	}

	// 3. claude_user_assignments: widen PK from (user_sub) to
	// (pool_id, user_sub). GORM's AutoMigrate already added the pool_id
	// COLUMN (default 'default') via AllTables; it never touches an existing
	// PK. Guarded so the ALTER only runs once — this is the single riskiest
	// DDL in the whole feature (an ALTER ... DROP PRIMARY KEY on a live
	// table), dry-run it against a prod-sized copy before shipping.
	var pkIsComposite int64
	db.Raw(`SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE
	         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'claude_user_assignments'
	           AND CONSTRAINT_NAME = 'PRIMARY' AND COLUMN_NAME = 'pool_id'`).Scan(&pkIsComposite)
	if pkIsComposite == 0 {
		if err := db.Exec(`UPDATE claude_user_assignments SET pool_id = ? WHERE pool_id = '' OR pool_id IS NULL`, defaultID).Error; err != nil {
			return fmt.Errorf("backfill claude_user_assignments.pool_id: %w", err)
		}
		if err := db.Exec(`ALTER TABLE claude_user_assignments DROP PRIMARY KEY, ADD PRIMARY KEY (pool_id, user_sub)`).Error; err != nil {
			return fmt.Errorf("widen claude_user_assignments PK: %w", err)
		}
	}

	// 4. claude_quota_tokens.pool_id already backfills to 'default' for every
	// pre-existing row via the column's own DEFAULT — nothing to do here.

	// 5. Every existing user becomes a primary member of "default".
	if err := db.Exec(`
		INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at)
		SELECT ?, id, TRUE, NOW() FROM users`, defaultID).Error; err != nil {
		return fmt.Errorf("backfill default pool members: %w", err)
	}
	return nil
}

// ── Lease-time / placement pool resolution ───────────────────────────────

// resolveUserPool decides which pool a lease or placement call draws from.
//
//  1. hint (from claude-proxy, extracted from a "claude-pool:<id>" PAT scope)
//     wins IFF the user is ACTUALLY a member of that pool. identity, not
//     claude-proxy, owns membership truth — a stale or foreign hint is
//     logged and ignored, never an error.
//  2. else the user's primary membership.
//  3. else (brand-new user, or a pre-migration edge case): lazily enroll
//     them as a primary member of "default" rather than requiring every
//     user-creation call site to remember to do it.
func resolveUserPool(userSub, hint string) (poolID, mode string) {
	if userSub == "" {
		return models.DefaultClaudePoolID, models.ClaudePoolModeDistributed // legacy/no-user_sub caller — today's behavior
	}
	if hint != "" {
		var m models.ClaudePoolMember
		if common.DB.Where("pool_id = ? AND user_sub = ?", hint, userSub).First(&m).Error == nil {
			return hint, poolModeOf(hint)
		}
		log.Printf("claude-pool: %s presented pool hint %q it is not a member of — ignoring, falling back to primary", userSub, hint)
	}
	var primary models.ClaudePoolMember
	if common.DB.Where("user_sub = ? AND is_primary = ?", userSub, true).First(&primary).Error == nil {
		return primary.PoolID, poolModeOf(primary.PoolID)
	}
	if err := common.DB.Exec(
		`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at) VALUES (?, ?, TRUE, ?)`,
		models.DefaultClaudePoolID, userSub, time.Now()).Error; err != nil {
		log.Printf("claude-pool: lazy default-enrollment failed for %s: %v", userSub, err)
	}
	return models.DefaultClaudePoolID, models.ClaudePoolModeDistributed
}

// poolModeOf reads a pool's Mode, defaulting to distributed on any lookup
// failure (fail open: a transient DB error must not silently switch a pool
// into concentration behavior it never asked for).
func poolModeOf(poolID string) string {
	var p models.ClaudePool
	if common.DB.Where("id = ?", poolID).First(&p).Error != nil {
		return models.ClaudePoolModeDistributed
	}
	return p.Mode
}

// ── PAT scope grantability ────────────────────────────────────────────────

// isClaudePoolScope reports whether rawScope names a specific pool the
// caller (userID) may mint a PAT for: the pool must EXIST and the caller
// must ALREADY be a member of it. Minting a PAT confers NO new access — it
// only lets the caller PRESENT, via a separate credential, access they
// already have via their browser session. Defense in depth only:
// InternalClaudeTokenLease independently re-checks membership server-side
// regardless (resolveUserPool's hint branch) — this gate just stops a
// confusing, unusable PAT from existing at all.
func isClaudePoolScope(userID, rawScope string) bool {
	id, ok := strings.CutPrefix(rawScope, "claude-pool:")
	if !ok {
		return false
	}
	return common.DB.Where("pool_id = ? AND user_sub = ?", id, userID).
		First(&models.ClaudePoolMember{}).Error == nil
}

// ── Admin CRUD ────────────────────────────────────────────────────────────

// AdminClaudePoolCreate creates a new pool. The caller becomes its
// OwnerSub — attribution only, see the file header.
//
// POST /api/v1/admin/claude-pools  (RequireAdmin)
// Body: {id, name, mode?, conservative_ceiling?}
func AdminClaudePoolCreate(c *gin.Context) {
	var body struct {
		ID                  string `json:"id"`
		Name                string `json:"name"`
		Mode                string `json:"mode"`
		ConservativeCeiling int    `json:"conservative_ceiling"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	id := strings.ToLower(strings.TrimSpace(body.ID))
	if !claudePoolIDPattern.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "id must match ^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$ — it is embedded in minted PAT scopes and is immutable after creation")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		fail(c, http.StatusBadRequest, 1400, "name required")
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		mode = models.ClaudePoolModeDistributed
	}
	if mode != models.ClaudePoolModeDistributed && mode != models.ClaudePoolModeConservative {
		fail(c, http.StatusBadRequest, 1400, `mode must be "distributed" or "conservative"`)
		return
	}
	if !validConservativeCeiling(body.ConservativeCeiling) {
		fail(c, http.StatusBadRequest, 1400, "conservative_ceiling must be a positive integer, 0 (inherit the global default), or -1 (explicitly unlimited)")
		return
	}
	owner, _ := currentUserID(c)
	pool := models.ClaudePool{
		ID: id, Name: name, Mode: mode, OwnerSub: owner,
		ConservativeCeiling: body.ConservativeCeiling,
	}
	if err := common.DB.Create(&pool).Error; err != nil {
		fail(c, http.StatusConflict, 1409, "create pool: "+err.Error())
		return
	}
	log.Printf("claude-pool: %s created pool %q (mode=%s)", owner, id, mode)
	ok(c, "ok", pool)
}

// AdminClaudePoolList lists every pool with its account/member counts.
//
// GET /api/v1/admin/claude-pools  (RequireAdmin)
func AdminClaudePoolList(c *gin.Context) {
	var pools []models.ClaudePool
	if err := common.DB.Order("created_at ASC").Find(&pools).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list pools: "+err.Error())
		return
	}
	type poolOut struct {
		models.ClaudePool
		OwnerEmail   string `json:"owner_email,omitempty"`
		AccountCount int64  `json:"account_count"`
		MemberCount  int64  `json:"member_count"`
	}
	out := make([]poolOut, 0, len(pools))
	for _, p := range pools {
		row := poolOut{ClaudePool: p}
		if p.OwnerSub != "" {
			common.DB.Raw(`SELECT email FROM users WHERE id = ?`, p.OwnerSub).Scan(&row.OwnerEmail)
		}
		common.DB.Model(&models.ClaudeQuotaToken{}).Where("pool_id = ?", p.ID).Count(&row.AccountCount)
		common.DB.Model(&models.ClaudePoolMember{}).Where("pool_id = ?", p.ID).Count(&row.MemberCount)
		out = append(out, row)
	}
	ok(c, "ok", gin.H{"pools": out})
}

// AdminClaudePoolUpdate patches a pool's name/mode/conservative_ceiling. The
// id (slug) itself is immutable — see AdminClaudePoolCreate.
//
// PATCH /api/v1/admin/claude-pools/:id  (RequireAdmin)
// Body: {name?, mode?, conservative_ceiling?}
func AdminClaudePoolUpdate(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	var pool models.ClaudePool
	if common.DB.Where("id = ?", id).First(&pool).Error != nil {
		fail(c, http.StatusNotFound, 1404, "no such pool: "+id)
		return
	}
	var body struct {
		Name                *string `json:"name"`
		Mode                *string `json:"mode"`
		ConservativeCeiling *int    `json:"conservative_ceiling"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	updates := map[string]interface{}{}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" {
			fail(c, http.StatusBadRequest, 1400, "name cannot be empty")
			return
		}
		updates["name"] = name
	}
	modeChanged := false
	if body.Mode != nil {
		mode := strings.TrimSpace(*body.Mode)
		if mode != models.ClaudePoolModeDistributed && mode != models.ClaudePoolModeConservative {
			fail(c, http.StatusBadRequest, 1400, `mode must be "distributed" or "conservative"`)
			return
		}
		if mode != pool.Mode {
			modeChanged = true
		}
		updates["mode"] = mode
	}
	if body.ConservativeCeiling != nil {
		if !validConservativeCeiling(*body.ConservativeCeiling) {
			fail(c, http.StatusBadRequest, 1400, "conservative_ceiling must be a positive integer, 0 (inherit the global default), or -1 (explicitly unlimited)")
			return
		}
		updates["conservative_ceiling"] = *body.ConservativeCeiling
	}
	if len(updates) == 0 {
		fail(c, http.StatusBadRequest, 1400, "nothing to update")
		return
	}
	if err := common.DB.Model(&pool).Updates(updates).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "update pool: "+err.Error())
		return
	}
	resp := gin.H{"id": id, "updated": updates}
	if modeChanged {
		var accountCount int64
		common.DB.Model(&models.ClaudeQuotaToken{}).Where("pool_id = ?", id).Count(&accountCount)
		if accountCount > 0 {
			resp["warning"] = "mode change takes effect on this pool's next placement pass (within the reclaim-loop tick), not synchronously"
		}
	}
	ok(c, "ok", resp)
}

// AdminClaudePoolDelete removes a pool. Refuses (409) if it still has
// accounts or members unless ?force=true, in which case both are
// reassigned to "default" in the same transaction first — never orphaned.
//
// DELETE /api/v1/admin/claude-pools/:id  (RequireAdmin)
func AdminClaudePoolDelete(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	if id == models.DefaultClaudePoolID {
		fail(c, http.StatusBadRequest, 1400, "the default pool cannot be deleted")
		return
	}
	var pool models.ClaudePool
	if common.DB.Where("id = ?", id).First(&pool).Error != nil {
		fail(c, http.StatusNotFound, 1404, "no such pool: "+id)
		return
	}
	force := c.Query("force") == "true"
	var accountCount, memberCount int64
	common.DB.Model(&models.ClaudeQuotaToken{}).Where("pool_id = ?", id).Count(&accountCount)
	common.DB.Model(&models.ClaudePoolMember{}).Where("pool_id = ?", id).Count(&memberCount)
	if (accountCount > 0 || memberCount > 0) && !force {
		fail(c, http.StatusConflict, 1409, fmt.Sprintf(
			"pool %s still has %d account(s) and %d member(s) — pass ?force=true to reassign both to %q and delete",
			id, accountCount, memberCount, models.DefaultClaudePoolID))
		return
	}
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		if accountCount > 0 {
			if err := tx.Model(&models.ClaudeQuotaToken{}).Where("pool_id = ?", id).
				Update("pool_id", models.DefaultClaudePoolID).Error; err != nil {
				return err
			}
		}
		if memberCount > 0 {
			// Reassigning membership to "default": a member who is ALREADY in
			// default just has this row dropped (no duplicate primary risk);
			// otherwise they join default as a non-primary member (their
			// existing primary, if any, is untouched).
			var members []models.ClaudePoolMember
			tx.Where("pool_id = ?", id).Find(&members)
			for _, m := range members {
				var already models.ClaudePoolMember
				if tx.Where("pool_id = ? AND user_sub = ?", models.DefaultClaudePoolID, m.UserSub).
					First(&already).Error != nil {
					if err := tx.Create(&models.ClaudePoolMember{
						PoolID: models.DefaultClaudePoolID, UserSub: m.UserSub, IsPrimary: false, AddedAt: time.Now(),
					}).Error; err != nil {
						return err
					}
				}
			}
			if err := tx.Where("pool_id = ?", id).Delete(&models.ClaudePoolMember{}).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&pool).Error
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete pool: "+err.Error())
		return
	}
	log.Printf("claude-pool: pool %q deleted (accounts=%d members=%d reassigned to %s)", id, accountCount, memberCount, models.DefaultClaudePoolID)
	ok(c, "ok", gin.H{"id": id, "deleted": true, "reassigned_accounts": accountCount, "reassigned_members": memberCount})
}

// AdminClaudePoolMembers lists a pool's members.
//
// GET /api/v1/admin/claude-pools/:id/members  (RequireAdmin)
func AdminClaudePoolMembers(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	var members []models.ClaudePoolMember
	if err := common.DB.Where("pool_id = ?", id).Order("added_at ASC").Find(&members).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list members: "+err.Error())
		return
	}
	type memberOut struct {
		UserSub   string    `json:"user_sub"`
		Email     string    `json:"email"`
		IsPrimary bool      `json:"is_primary"`
		AddedAt   time.Time `json:"added_at"`
	}
	out := make([]memberOut, 0, len(members))
	for _, m := range members {
		var email string
		common.DB.Raw(`SELECT email FROM users WHERE id = ?`, m.UserSub).Scan(&email)
		out = append(out, memberOut{UserSub: m.UserSub, Email: email, IsPrimary: m.IsPrimary, AddedAt: m.AddedAt})
	}
	ok(c, "ok", gin.H{"pool_id": id, "members": out})
}

// AdminClaudePoolAddMember adds a user to a pool, by user_sub or email.
//
// POST /api/v1/admin/claude-pools/:id/members  (RequireAdmin)
// Body: {user_sub | email, is_primary?}
func AdminClaudePoolAddMember(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	var pool models.ClaudePool
	if common.DB.Where("id = ?", id).First(&pool).Error != nil {
		fail(c, http.StatusNotFound, 1404, "no such pool: "+id)
		return
	}
	var body struct {
		UserSub string `json:"user_sub"`
		Email   string `json:"email"`
		// Pointer, not bool: distinguishes "caller expressed no opinion" from
		// "caller explicitly asked for false". A plain bool defaulted to false
		// on omission, so re-invoking this endpoint as an idempotent "ensure
		// member" call (no is_primary in the body) on an ALREADY-primary
		// member silently demoted them via the OnConflict update — fixed
		// below by only touching the is_primary column when this is non-nil.
		IsPrimary *bool `json:"is_primary"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	userSub := strings.TrimSpace(body.UserSub)
	if userSub == "" && body.Email != "" {
		email := strings.ToLower(strings.TrimSpace(body.Email))
		if err := common.DB.Raw(`SELECT id FROM users WHERE email = ?`, email).Scan(&userSub).Error; err != nil || userSub == "" {
			fail(c, http.StatusNotFound, 1404, "no such user: "+email)
			return
		}
	}
	if userSub == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub or email required")
		return
	}
	admin, _ := currentUserID(c)
	// Retried: this transaction's UPDATE (clear other primaries for userSub)
	// + INSERT (this pool's row) touches overlapping rows for the SAME user
	// across DIFFERENT pool_ids, so two admins (or a provisioning script)
	// adding the SAME user to DIFFERENT pools concurrently can lock-order
	// against each other — a stress test reproduced a 7/8 failure rate under
	// an 8-way concurrent race before this retry was added. MySQL 1213 is
	// retryable by design (the server picks a victim so someone progresses);
	// reuses the general-purpose retryTxConflict already used for the
	// structurally similar me_app_intents contention (me_intents_db.go).
	err := retryTxConflict("claude-pool: add member "+userSub+" to "+id, func() error {
		return common.DB.Transaction(func(tx *gorm.DB) error {
			var totalCount int64
			if err := tx.Model(&models.ClaudePoolMember{}).Where("user_sub = ?", userSub).Count(&totalCount).Error; err != nil {
				return err
			}
			// A user's very first-ever membership MUST be primary — every user
			// must have exactly one, which resolveUserPool depends on — so force
			// it regardless of what the caller passed (or omitted).
			forcedFirst := totalCount == 0
			makePrimary := forcedFirst || (body.IsPrimary != nil && *body.IsPrimary)
			touchPrimary := forcedFirst || body.IsPrimary != nil
			if makePrimary {
				if err := tx.Model(&models.ClaudePoolMember{}).Where("user_sub = ?", userSub).
					Update("is_primary", false).Error; err != nil {
					return err
				}
			}
			conflict := clause.OnConflict{Columns: []clause.Column{{Name: "pool_id"}, {Name: "user_sub"}}}
			if touchPrimary {
				conflict.DoUpdates = clause.AssignmentColumns([]string{"is_primary"})
			} else {
				// Caller expressed no opinion and this isn't a brand-new user —
				// an idempotent re-add of an EXISTING membership must leave
				// is_primary exactly as it is, never reset it via the upsert.
				conflict.DoNothing = true
			}
			return tx.Clauses(conflict).Create(&models.ClaudePoolMember{
				PoolID: id, UserSub: userSub, IsPrimary: makePrimary, AddedAt: time.Now(), AddedBy: admin,
			}).Error
		})
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "add member: "+err.Error())
		return
	}
	// Re-read rather than assume: when the upsert took the DoNothing path
	// (existing member, caller expressed no opinion), what changed inside
	// the transaction doesn't tell us the row's actual final state.
	var final models.ClaudePoolMember
	common.DB.Where("pool_id = ? AND user_sub = ?", id, userSub).First(&final)
	log.Printf("claude-pool: %s added/confirmed %s in pool %q (primary=%v)", admin, userSub, id, final.IsPrimary)
	ok(c, "ok", gin.H{"pool_id": id, "user_sub": userSub, "is_primary": final.IsPrimary})
}

// AdminClaudePoolRemoveMember removes a user from a pool. Refuses (409) if
// this is the user's ONLY membership — every user must remain a member of
// at least one pool. If it is their primary and they have others, the
// earliest remaining row is auto-promoted to primary in the same
// transaction, and the response says which one.
//
// DELETE /api/v1/admin/claude-pools/:id/members/:user_sub  (RequireAdmin)
func AdminClaudePoolRemoveMember(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	userSub := strings.TrimSpace(c.Param("user_sub"))
	var target models.ClaudePoolMember
	if common.DB.Where("pool_id = ? AND user_sub = ?", id, userSub).First(&target).Error != nil {
		fail(c, http.StatusNotFound, 1404, "not a member")
		return
	}
	var all []models.ClaudePoolMember
	common.DB.Where("user_sub = ?", userSub).Order("added_at ASC").Find(&all)
	if len(all) <= 1 {
		fail(c, http.StatusConflict, 1409, "refusing to remove a user's only pool membership — every user must belong to at least one pool")
		return
	}
	var promoted string
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("pool_id = ? AND user_sub = ?", id, userSub).Delete(&models.ClaudePoolMember{}).Error; err != nil {
			return err
		}
		if target.IsPrimary {
			for _, m := range all {
				if m.PoolID != id {
					promoted = m.PoolID
					return tx.Model(&models.ClaudePoolMember{}).
						Where("pool_id = ? AND user_sub = ?", m.PoolID, userSub).
						Update("is_primary", true).Error
				}
			}
		}
		return nil
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "remove member: "+err.Error())
		return
	}
	resp := gin.H{"pool_id": id, "user_sub": userSub, "removed": true}
	if promoted != "" {
		resp["promoted_primary"] = promoted
	}
	ok(c, "ok", resp)
}

// AdminClaudePoolSetPrimary makes this the user's primary pool, flipping
// every other membership row for that user to non-primary in the same
// transaction — the generated-column unique index on claude_pool_members
// makes a half-done flip impossible even under a mid-transaction crash.
//
// POST /api/v1/admin/claude-pools/:id/members/:user_sub/primary  (RequireAdmin)
func AdminClaudePoolSetPrimary(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	userSub := strings.TrimSpace(c.Param("user_sub"))
	var target models.ClaudePoolMember
	if common.DB.Where("pool_id = ? AND user_sub = ?", id, userSub).First(&target).Error != nil {
		fail(c, http.StatusNotFound, 1404, "not a member")
		return
	}
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ClaudePoolMember{}).Where("user_sub = ? AND pool_id <> ?", userSub, id).
			Update("is_primary", false).Error; err != nil {
			return err
		}
		return tx.Model(&models.ClaudePoolMember{}).Where("pool_id = ? AND user_sub = ?", id, userSub).
			Update("is_primary", true).Error
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "set primary: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"pool_id": id, "user_sub": userSub, "is_primary": true})
}
