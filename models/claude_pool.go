package models

import (
	"time"

	"gorm.io/gorm"
)

// Pool modes. See ClaudePool.Mode.
const (
	ClaudePoolModeDistributed  = "distributed"
	ClaudePoolModeConservative = "conservative"
	// DefaultClaudePoolID is the pool every pre-existing account/user is
	// backfilled into (EnsureDefaultClaudePool), and the fallback for a
	// lease/placement call that resolves no other pool.
	DefaultClaudePoolID = "default"
)

// ClaudePool is a partition of the shared Claude account pool: a set of
// accounts (ClaudeQuotaToken.PoolID, one-pool-per-account — a subscription
// credential is a single resource, so ambiguous pool ownership would make
// "which mode/ceiling applies to this account" ambiguous) and a set of
// member users (ClaudePoolMember, many-to-many — a user MAY draw from more
// than one pool, e.g. a second PAT scoped to a pool for testing).
//
// Mode governs BOTH placement (claude_balance.go's EnsureAssignments) and
// lease-time ordering (InternalClaudeTokenLease's sortKey) for every account
// in this pool:
//   - "distributed" — today's unchanged algorithm: greedy-LPT placement +
//     HRW-rendezvous lease-time spreading across every servable account.
//   - "conservative" — accounts are used in a fixed order (PoolSortOrder,
//     then CreatedAt); ALL new placements concentrate on the first
//     non-exhausted account, rolling to the next only once it is genuinely
//     unhealthy/exhausted — never on headcount alone, though
//     ConservativeCeiling still bounds how many NEW users may pile onto the
//     current account as an anti-concentration backstop.
type ClaudePool struct {
	// ID is a slug (e.g. "default", "eu-overflow"), IMMUTABLE after creation:
	// it is embedded verbatim in minted PAT scopes as "claude-pool:<ID>", so
	// renaming it would silently orphan every PAT already carrying that
	// scope. Rename via Name instead.
	ID   string `gorm:"column:id;type:varchar(64);primaryKey" json:"id"`
	Name string `gorm:"column:name;size:128;not null"          json:"name"`
	// Mode: "distributed" | "conservative". See type doc above.
	Mode string `gorm:"column:mode;size:16;not null;default:'distributed'" json:"mode"`
	// OwnerSub — users.id of the admin who created this pool. ATTRIBUTION
	// ONLY: who to ask about this pool, shown in the admin UI. It is
	// deliberately NOT an authorization boundary — every pool CRUD endpoint
	// stays plain RequireAdmin, matching how an admin can already
	// add/remove/drain any account org-wide today. The seeded "default" pool
	// (the one pre-existing pool, migrated in place) is owned by
	// admin@lum.id, the account that actually holds those subscriptions.
	OwnerSub string `gorm:"column:owner_sub;size:36;index" json:"owner_sub,omitempty"`
	// ConservativeCeiling overrides the global default
	// (LUMID_CLAUDE_CONSERVATIVE_CEILING, default 6) for this pool's
	// anti-concentration backstop. 0 = use the global default. Meaningless
	// in distributed mode, kept unconditionally so a mode toggle back to
	// conservative doesn't need the value re-entered.
	ConservativeCeiling int `gorm:"column:conservative_ceiling;not null;default:0" json:"conservative_ceiling"`
	// AllowOnprem — may this pool's members reach the SELF-HOSTED models
	// (the GB10 fleet behind lumid-llm: deepseek-v4-flash et al)?
	//
	// Orthogonal to everything else on this struct: Mode/ConservativeCeiling
	// govern how POOLED ANTHROPIC accounts are chosen, which has nothing to do
	// with our own GPUs. A pool is simply the unit we already have for "who may
	// draw on what", so on-prem access hangs here too.
	//
	// DEFAULTS TRUE, and the default is load bearing: on-prem is open to every
	// role today (that is the entire point of owning the fleet — see
	// selfHostedModels in claude-proxy), so anything other than true would be a
	// silent estate-wide revocation on migration. AutoMigrate ADDs the column
	// with this DB-level default, so existing rows come out true without a
	// backfill.
	//
	// TRAP when setting it false: an ordinary role=user member has their
	// claude-sonnet*/claude-haiku* rewritten to deepseek-v4-flash BEFORE the
	// model gate (aliasClaudeForRole), so denying on-prem leaves them with NO
	// usable model at all — pooled Sonnet is admin-only. AdminClaudePoolUpdate
	// warns when the pool has such members; it does not refuse, because a pool
	// of admins is a legitimate case.
	AllowOnprem bool `gorm:"column:allow_onprem;not null;default:true" json:"allow_onprem"`
	// AllowOpenrouter — may this pool's members reach EXTERNALLY BILLED models
	// (OpenRouter-served ids, kimi-k3, …)?
	//
	// DEFAULTS FALSE, and note this is the OPPOSITE default to AllowOnprem
	// directly above. Both encode the same rule — preserve today's behaviour
	// when nobody has expressed an opinion — and today those behaviours differ:
	// claude-proxy's denyExternalModelForRole currently refuses every
	// externally-billed model to EVERY role, admin included, while on-prem is
	// open to everyone. So on-prem defaults open and this defaults closed.
	// Getting either backwards is a silent estate-wide change on migration, and
	// for this one it is a change that spends real money.
	//
	// This flag is an opt-IN: setting it true re-opens externally-billed models
	// for one pool without lifting the block for anybody else.
	AllowOpenrouter bool           `gorm:"column:allow_openrouter;not null;default:false" json:"allow_openrouter"`
	CreatedAt       time.Time      `gorm:"autoCreateTime"                                  json:"created_at"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime"                                  json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"column:deleted_at;index"                         json:"-"`
}

func (ClaudePool) TableName() string { return "claude_pools" }

// ClaudePoolMember is the many-to-many user<->pool join. A user may hold
// several rows (multi-pool membership); AT MOST ONE may carry IsPrimary=true
// — enforced at the DB layer by a generated-column unique index (see
// EnsureDefaultClaudePool's raw DDL: MySQL unique indexes never collide on
// NULL, so only the IsPrimary=true rows compete for uniqueness), not by
// GORM, which cannot express a partial-unique constraint.
//
// IsPrimary is the pool used when a request carries no explicit
// "claude-pool:<id>" PAT scope — i.e. every browser/JWT-authenticated
// request, and every PAT that isn't deliberately scoped to a non-primary
// pool. See resolveUserPool in claude_pool_admin.go.
type ClaudePoolMember struct {
	PoolID    string `gorm:"column:pool_id;size:64;primaryKey"                     json:"pool_id"`
	UserSub   string `gorm:"column:user_sub;size:36;primaryKey;index:idx_cpm_user" json:"user_sub"`
	IsPrimary bool   `gorm:"column:is_primary;not null;default:false"              json:"is_primary"`
	// IsManager — may this member administer THIS POOL's Claude accounts:
	// pause/resume them, and reset the usage clock for this pool's members?
	//
	// A delegated slice of two powers that are otherwise admin/super_admin and
	// estate-wide. Scoped to (pool, user) precisely so a delegate can never
	// reach an account or a member outside the pool they were given — the
	// grant IS the scope, rather than a role that would carry estate-wide.
	//
	// Granting is super_admin, matching pool creation and reset-window: those
	// are the "hand out capacity" decisions, and handing out the power to
	// reset a usage clock is the same act one level removed. Being a manager
	// confers NO platform role: parseScope and computeAccess never see it, and
	// it grants nothing outside the two pool-scoped endpoints in
	// claude_pool_manager.go.
	IsManager bool      `gorm:"column:is_manager;not null;default:false"              json:"is_manager"`
	AddedAt   time.Time `gorm:"column:added_at;autoCreateTime"                        json:"added_at"`
	// AddedBy — the admin sub who added this membership (audit only; empty
	// for rows created by the migration backfill or by lazy self-enrollment).
	AddedBy string `gorm:"column:added_by;size:36" json:"added_by,omitempty"`
}

func (ClaudePoolMember) TableName() string { return "claude_pool_members" }
