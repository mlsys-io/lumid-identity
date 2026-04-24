# Unified auth — `lumid_auth` shared hook library (spec)

Status: **design, pre-implementation**. This spec describes what the
`lumid_auth` Python package looks like when we collapse FlowMesh's and
Lumilake's auth modules into one library. The package is not yet
written — this document is the contract the refactor PR will satisfy.

The motivation: FlowMesh and Lumilake already converged so hard on
identical auth shapes (3-part HMAC-stored keys, identical
`PrincipalContext`, identical `lumid_introspect.py` bridges) that a
shared library is a no-op structurally and a big win for coherence.
Each service currently carries ~400 LOC of auth plumbing; after the
refactor the service-side is ~10 lines of dependency wiring plus the
per-service scope vocabulary.

## 1. Namespaced scope convention

All cross-service PATs minted at
`POST /api/v1/identity/personal-access-tokens` use this vocabulary:

```
<service>:*                 → full access to one service
<service>:<resource>:<verb> → fine-grained, e.g. flowmesh:workflows:submit
*                           → global admin (role=admin users only)
```

The `*` wildcard is reserved for users whose `role=admin` in the
lum.id `users` table — any other user who requests it during PAT
mint should have the PAT rejected or silently downgraded. (Current
`POST /personal-access-tokens` does no scope whitelisting; that's a
follow-up hardening.)

Reserved service namespaces:

| Namespace | Owner service | Replaces legacy credential |
|-----------|---------------|----------------------------|
| `flowmesh:*`, `flowmesh:workflows:submit`, `flowmesh:workflows:cancel`, `flowmesh:workers:manage`, `flowmesh:guardians:register`, `flowmesh:results:read`, `flowmesh:results:write`, `flowmesh:system:metrics` | FlowMesh | `flm-*` keys |
| `lumilake:*`, `lumilake:jobs:submit`, `lumilake:jobs:cancel`, `lumilake:trace:read`, `lumilake:metadata:write`, `lumilake:principals:manage` | Lumilake | `lmk-*` keys |
| `xpcloud:*`, `xpcloud:repos:read`, `xpcloud:repos:write`, `xpcloud:repos:admin`, `xpcloud:pulls:open`, `xpcloud:pulls:merge` | xpcloud | PAT-only already |
| `qa:*`, `qa:trading:submit`, `qa:leaderboard:read`, `qa:admin:*` | QuantArena | PAT-only already |
| `runmesh:admin`, `runmesh:billing:*` | Runmesh | Sa-Token SSO already |

**Role shortcut.** lum.id `role=admin` is treated as `*` across every
service hook regardless of the scope list. This avoids admin PATs
needing `["flowmesh:*","lumilake:*","xpcloud:*","qa:*"]` spelled out.

**Multi-scope PATs.** A single PAT carries multiple namespaces, e.g.
`["flowmesh:workflows:submit","lumilake:jobs:submit"]`. Each service
hook filters to its own namespace and silently drops the rest.

## 2. Shared `PrincipalContext`

The dataclass matches what FlowMesh + Lumilake already use (with two
additive fields for lum.id metadata). Importable from `lumid_auth`:

```python
@dataclass(frozen=True)
class PrincipalContext:
    principal_id: str       # "lumid:<sub>" for lum.id-issued;
                            # "<service>:<local_id>" for legacy keys
                            # during migration
    org_id: str             # "lumid" for lum.id-issued; real tenant
                            # id for legacy
    external_id: str        # lum.id sub (UUID) or legacy external id
    principal_type: str     # "user", "service", "admin"
    scopes: list[str]       # service-local vocabulary AFTER
                            # namespace stripping
    email: str = ""         # lum.id only
    role: str = ""          # lum.id only: "user" | "admin"
```

No behavior lives on the dataclass. Everything scope- or role-related
is a function on the `LumidAuth` object.

## 3. The hook library contract

`lumid_auth` exports three things and nothing else:

```python
from lumid_auth import LumidAuth, PrincipalContext, ALLOWED_SCOPES
```

### 3.1 Construction — once per service process

```python
# src/host/auth/__init__.py   (FlowMesh example)
import os
from lumid_auth import LumidAuth

auth = LumidAuth(
    service="flowmesh",
    lumid_url=os.getenv("LUMID_IDENTITY_URL", "https://lum.id"),

    # ── optional: accept legacy prefix during migration window ──
    # During the first N months after adoption, tokens minted
    # *before* the cutover still work. After `recordIntrospectAudit`
    # shows zero traffic with this prefix, drop this param + delete
    # the local key tables.
    legacy_prefixes=("flm",),

    # ── optional: map a lum.id scope to one the service uses locally,
    # when namespace discipline isn't enough. Usually empty.
    scope_aliases={},
)
```

### 3.2 Use — FastAPI dependencies

```python
# Any authenticated caller (PAT or JWT cookie):
@router.get("/api/v1/workers")
async def list_workers(p = Depends(auth.require_any())): ...

# Scoped write — service-local verb after namespace strip:
@router.post("/api/v1/workflows")
async def submit(p = Depends(auth.require_scope("workflows:submit"))): ...

# Multi-scope (any of):
@router.get("/api/v1/system/metrics")
async def metrics(p = Depends(
    auth.require_any_scope("system:metrics", "*"))): ...

# Admin role (short for require_scope("*") + role gate):
@router.delete("/api/v1/principals/{id}")
async def delete_principal(p = Depends(auth.require_role("admin"))): ...
```

### 3.3 Internals — what `LumidAuth.authenticate(raw_bearer)` does

1. Parse `Authorization: Bearer <token>` (via `HTTPBearer` like today's
   `deps.py`). Missing/non-Bearer → 401.
2. **Legacy fast path.** If `raw_bearer` matches
   `<legacy_prefix>-<4hex>-<32chars>` AND `legacy_prefixes` is set,
   delegate to the service's legacy table lookup (service injects a
   callable — see § 3.4). If not found, fall through to lum.id rather
   than 401 (a legacy-looking string could be a false positive on a
   lum.id JWT, e.g. `flm-*`-prefixed names don't exist but a customer
   could craft them; be permissive).
3. **JWT path.** If the token has three dot-segments, fetch
   `{lumid_url}/.well-known/jwks.json` (1 h cache, kid-indexed),
   verify the signature locally. On success, read `claims.sub`,
   `claims.email`, `claims.role`, `claims.scopes` (JSON array claim).
4. **PAT path.** Otherwise `POST {lumid_url}/oauth/introspect` with
   a **form** body `token=<raw_bearer>` (this matches current
   behavior — lumid-identity accepts both form and JSON). Cache the
   response for 60 s keyed by SHA-256(token).
5. **Scope mapping.** For every returned scope:
   - `*` → `*`
   - `<service>:*` → `*`
   - `<service>:x:y` → `x:y` (namespace-strip)
   - Anything else → drop.
6. **Role override.** If `role == "admin"`, replace scope list with
   `["*"]` (ignoring whatever was granted).
7. Return a `PrincipalContext`.

### 3.4 Legacy table callback (only during migration window)

Because FlowMesh's legacy keys live in PostgreSQL and Lumilake's in
its own governance DB, the library takes a callback:

```python
async def my_legacy_lookup(prefix: str, key_hash: str) -> PrincipalContext | None:
    """Return PrincipalContext or None. Service-specific."""
    row = await db.lookup(prefix, key_hash)
    if not row: return None
    return PrincipalContext(...)

auth = LumidAuth(service="flowmesh", legacy_prefixes=("flm",),
                 legacy_lookup=my_legacy_lookup)
```

When `legacy_prefixes` is empty, the callback is never invoked and
services can safely drop their key tables.

## 4. Migration recipe (for the future refactor PR, not this wave)

Step-by-step, two-repo PR. Each step is independently revertable.

1. **Publish `lumid_auth`** under `/proj/lumid_identity/python/lumid_auth/`.
   Vendor into each service's `pyproject.toml` via a local path, or
   publish to a private PyPI. Package contents:
   - `lumid_auth/__init__.py` — exports `LumidAuth, PrincipalContext, ALLOWED_SCOPES`.
   - `lumid_auth/auth.py` — `LumidAuth` class with FastAPI dependency factories.
   - `lumid_auth/introspect.py` — PAT introspect + 60 s cache.
   - `lumid_auth/jwks.py` — JWKS fetch + JWT verify + 1 h cache.
   - `lumid_auth/scopes.py` — namespace strip + role override.
   - `tests/` — unit tests covering all four paths (JWT happy,
     PAT happy, legacy-prefix fallthrough, scope mapping).

2. **Flip FlowMesh.** Replace
   `src/host/auth/security.py::authenticate_api_key` body with a call
   to `auth.authenticate(raw_key)`. Move the FlowMesh-local key table
   lookup into a `legacy_lookup` callback. Delete
   `src/host/auth/lumid_introspect.py`. Leave `APIKey` / `Principal`
   tables intact — `legacy_prefixes=("flm",)` keeps them alive during
   sunset.

3. **Flip Lumilake.** Same refactor with `legacy_prefixes=("lmk",)`.
   Delete `src/lumilake/server/auth/lumid_introspect.py`.

4. **Observe sunset.** `recordIntrospectAudit` in
   `/proj/lumid_identity/internal/handler/introspect.go` already logs
   every PAT prefix it sees. Watch the counter. When
   `lumid_introspect_total{prefix="flm"}` hits zero for a week, open a
   follow-up PR that drops the `legacy_prefixes` param in the service
   call and runs an Alembic migration to drop the local key tables.

Expected LOC impact (measured against current trees):

| Repo | Before | After | Delta |
|------|--------|-------|-------|
| `flowmesh/src/host/auth/` | ~420 | ~60 | −360 |
| `lumilake/src/lumilake/server/auth/` | ~370 | ~55 | −315 |
| `lumid_identity/python/lumid_auth/` | 0 | ~320 | +320 |

Net: −355 LOC, one canonical implementation, one test surface.

## 5. What this spec explicitly doesn't do

- **Does not touch `flowmeshctl` (`yao.lu/flowmesh.zip`)** — the
  deployment CLI correctly ships `admin_api_key`/`guardian_api_key`
  in YAML because those are *bootstrap* credentials for a fresh Host,
  before any user exists. Bootstrap keys stay local; user-facing PATs
  are all lum.id-minted.
- **Does not unify the gRPC `GUARDIAN_TOKEN`** — that's internal
  service-to-service, different threat model, different rotation
  cadence.
- **Does not define the admin UI** for minting namespaced-scope PATs.
  `lum.id/account/tokens` today is a plain textarea; a per-service
  scope picker is a separate UI PR.
- **Does not gate PAT-mint scope whitelisting** — pat.go currently
  accepts any opaque scope string. Hardening (reject `*` unless
  `role=admin`; reject unknown namespaces) is a follow-up.
- **Does not cover service-to-service tokens** (e.g. FlowMesh Host
  calling Lumilake on behalf of a user). That's Phase 6.

## 6. How this spec is validated

The live integration tests in `/proj/LumidOS/LumidOS/tests/integration/`:

- **TC24 (`test_case_24_unified_auth.py`)** — proves one PAT hits six
  layers (lumid-identity, QA, Runmesh, xpcloud, FlowMesh, Lumilake)
  and that namespace filtering gates cross-service access.
- **TC20 (`test_case_20_whole_stack_golden_path.py`)** — exercises the
  same PAT through xp.io app install, FlowMesh workflow submission,
  and Lumilake job preview within a single narrative run.

If either of those regresses, the contract above has drifted and the
spec needs revision before the refactor PR lands.
