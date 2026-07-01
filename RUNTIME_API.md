# runtime-api — decoupling the runtime dashboard from the website (UKS migration)

Design + scaffold for **Work item 1** of the UKS migration (`/proj/infra/MIGRATION.md`): split the
runtime-dashboard reads/writes out of the public website so the website (WEB) and the runtime (CORE) can run on
different machines. Today `lumid_identity`'s `me_*` handlers read the runtime filesystem off a **bind-mount of
the operator+tenant home** (`/home/luyao` + `/home/webmaster`), which is the sole thing coupling website↔runtime.

## Target
- **`runtime-api`** = the same `lumid_identity` binary run with **`-runtime-only`** (a build tag / flag), serving
  **only** the runtime-dashboard routes, reading its **local** filesystem on the **CORE PVC** (`/state`), and
  validating the caller's lum.id JWT via **shared JWKS** (public keys only — no DB, no signing keys on CORE).
- **WEB** keeps auth-core (`/login`, `/oauth/*`, PATs, JWKS, admin/users, everything else) and **proxies** the
  runtime routes to the CORE `runtime-api` Service.
- **The `/home` bind-mount is removed from the WEB identity container** — the acceptance test for "decoupled."

## Routes that move to runtime-api (read/write the runtime FS)
From `internal/handler/router.go` (the `me` group) + `admin_loops.go`:
```
GET  /api/v1/me/cycles                             MeCyclesList
GET  /api/v1/me/cycles/:app/:loop/:ts              MeCycleDetail
GET  /api/v1/me/cycles/:app/:loop/:ts/search       MeCycleLogSearch
GET  /api/v1/me/cycles/:app/:loop/:ts/provenance   MeCycleProvenance
POST /api/v1/me/cycles/feedback                    MeCycleFeedback        (write → feedback.jsonl)
GET  /api/v1/me/apps/:app/cycle-log                MeCycleLog
GET  /api/v1/me/apps/:app/experiments[...]         MeAppExperiments / MeAppExperiment / MeAppExperimentCase
GET  /api/v1/me/experiments                        MeExperiments
GET  /api/v1/me/apps/:app/casebook[...]            MeCasebook / MeCaseLog / MeCaseReport
GET  /api/v1/me/apps/:app/datasets, /dataset-file  MeAppDatasets / MeAppDatasetFile
GET  /api/v1/me/knowledge (+ agent banks)          MeKnowledge (me_knowledge.go)
GET  /api/v1/admin/loops                           admin_loops.go (xpio_state.json + manifest walk)
```
All of these resolve paths through **`runtime_paths.go::ResolveRuntimeReadPath/WritePath`** →
`bundleRootCandidates(appDir)`. The only change they need is **where `appDir`'s base root comes from**.

## The one behavioural change: root from env, not the operator home
- Today the base roots come from `operatorHome()`/`tenantRoot()` (in `me_apps.go`), i.e. `LUMID_OPERATOR_HOME`
  (`/home/luyao`) + `/home/webmaster/.tenants/<sub>`.
- Under runtime-api on CORE, point them at the **PVC**:
  - `XP_HOME=/state/.xp`  (operator KG + app bundles)
  - `TENANTS_ROOT=/state/.tenants`  (tenant installs)
- Implement: have `operatorHome()`/`tenantRoot()` honour `XP_HOME`/`TENANTS_ROOT` when set (fall back to the
  legacy home for the non-split/dev path). No handler logic changes — only the root source.

## Scaffold steps (implementation checklist)
1. **`-runtime-only` flag in `cmd/identity/main.go`** (or `//go:build runtimeonly`): when set, skip DB/Redis/
   signing-key open; `LoadJWKS(cfg.IdentityURL)` for verification only; register **only** the runtime route
   subset (factor the block in `router.go` into `RegisterRuntimeRoutes(r)` and call just that).
2. **Env roots:** `operatorHome()`/`tenantRoot()` read `XP_HOME`/`TENANTS_ROOT` first.
3. **Dockerfile:** add `ARG RUNTIME_ONLY=0` → the build/entrypoint passes `-runtime-only` when `=1`
   (build-push.sh already builds `ghcr.io/mlsys-io/runtime-api` with `--build-arg RUNTIME_ONLY=1`).
4. **WEB proxy:** WEB's edge/nginx proxies the routes above to `RUNTIME_API_UPSTREAM` (the CORE Service,
   `core.core.svc:8080`) — see `infra/k8s/charts/web` (`RUNTIME_API_UPSTREAM` env + `ingress.runtimePaths`).
5. **Remove the `/home` bind-mount** from the WEB identity Deployment; CORE mounts the PVC at `/state`.
6. **Verify:** a Studio cycle/experiment/knowledge view loads on WEB with **no `/home` mount**; posting cycle
   feedback lands on the CORE PVC (`/state/.../.lumid/.../feedback.jsonl`).

## Non-goals / notes
- `xpcloud` is already decoupled (git repos + HTTP `ingest/memories` & `inbox/message`) — unchanged.
- CORE is the **single writer** of `/state`; the PVC is `ReadWriteOnce`; never run two runtime-api writers.
- This is a service **split of existing handlers**, not a rewrite — keep the handler bodies as-is.
