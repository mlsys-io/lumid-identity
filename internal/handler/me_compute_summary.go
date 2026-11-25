package handler

// GET /me/compute — fleet capacity as COUNTS ONLY, for every signed-in user,
// so Studio can show the compute behind a run.
//
// WHY SERVER-SIDE. The fleet inventory is the mesh-federator's merged
// /fm/api/v1/workers, which the edge gates at admin+ (it discloses hostnames,
// GPU models, cost_per_hour, cached models and env). A normal user gets 403
// there, and a per-site call with their own token answers 200 with an EMPTY
// array, which renders as an outage. So identity reads the inventory on their
// behalf and returns only what is safe for anyone to see: per (site, kind)
// totals of busy and idle units, and which sites answered.
//
// WHAT NEVER LEAVES. Nothing per worker: no hostnames, node or worker ids,
// aliases, IPs, costs, models, tags, or the federator's per-site error text
// (which can name a host). computeSummaryFrom builds the response from scratch
// out of counts; it never copies a worker field through.
//
// WHO IT READS AS. A bridge JWT for one operator principal — the user whose
// email is LUMID_COMPUTE_SUMMARY_AS (default admin@lum.id) — with the single
// read scope flowmesh:workers:read. If that user does not exist, is
// suspended, or the read fails, the answer is 503: there is no fallback to
// the caller's own token or to any broader credential.
//
// WHERE. FLOWMESH_FEDERATOR_URL (default the in-cluster federator Service,
// http://mesh-federator.lumid.svc.cluster.local:9400/fm — the same upstream
// lum.id/fm/api/v1/ proxies to). It is deliberately NOT FLOWMESH_BASE_URL:
// that names one FlowMesh host (the cloud one, which has no workers), not the
// federated fleet.
//
// COST. One upstream call per 30 s per replica no matter how many pages poll:
// the summary is the same for every caller, so it is cached once, and
// concurrent misses share one in-flight call. A failure is remembered for a
// few seconds so a page polling a dead federator does not hammer it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	computeSummaryAsEnv     = "LUMID_COMPUTE_SUMMARY_AS"
	computeSummaryAsDefault = "admin@lum.id"
	computeFederatorEnv     = "FLOWMESH_FEDERATOR_URL"
	computeFederatorDefault = "http://mesh-federator.lumid.svc.cluster.local:9400/fm"
	computeUnavailableMsg   = "compute capacity unavailable"
	computeMaxBody          = 8 << 20
)

// Vars so tests can tighten them.
var (
	computeSummaryTTL      = 30 * time.Second
	computeSummaryFailTTL  = 5 * time.Second
	computeUpstreamTimeout = 10 * time.Second
)

// computeSummaryScopes is all the summary needs: list workers. Not the rental
// scopes — this bearer can never create, cancel or read a task.
var computeSummaryScopes = []string{"flowmesh:workers:read"}

// computeSummaryUser looks up the operator principal by email; a var so
// tests can stand in for the database.
var computeSummaryUser = func(email string) (models.User, error) {
	var u models.User
	if common.DB == nil {
		return u, errors.New("no database")
	}
	err := common.DB.Where("email = ?", email).Take(&u).Error
	return u, err
}

// ComputeCapacity is one (site, kind) row. Kind is the GPU device name, or
// "CPU" for a worker without GPUs. A GPU kind counts GPUs (a worker's status
// applies to every GPU it holds); "CPU" counts workers.
type ComputeCapacity struct {
	Site  string `json:"site"`
	Kind  string `json:"kind"`
	Total int    `json:"total"`
	Busy  int    `json:"busy"`
	Idle  int    `json:"idle"`
}

// ComputeSite says whether a site answered the federator's fan-out. ok:false
// means "unknown", not "empty".
type ComputeSite struct {
	Site string `json:"site"`
	OK   bool   `json:"ok"`
}

// ComputeSummary is the whole response body's data.
type ComputeSummary struct {
	Capacity []ComputeCapacity `json:"capacity"`
	Sites    []ComputeSite     `json:"sites"`
	AsOf     string            `json:"as_of"`
}

// fmFleetWorker is the slice of a federator worker the summary reads. Every
// other field is dropped at decode time.
type fmFleetWorker struct {
	Site     string `json:"site"`
	Status   string `json:"status"`
	Hardware *struct {
		GPU *struct {
			Devices []struct {
				Name string `json:"name"`
			} `json:"devices"`
		} `json:"gpu"`
	} `json:"hardware"`
}

type fmFleetSite struct {
	Site string `json:"site"`
	OK   bool   `json:"ok"`
}

// computeSummaryFrom aggregates workers into counts. It is the ONLY place a
// response row is built, and it copies no per-worker field but site, status
// (into a count) and the GPU model name (into kind).
func computeSummaryFrom(workers []fmFleetWorker, sites []fmFleetSite, now time.Time) ComputeSummary {
	type key struct{ site, kind string }
	agg := map[key]*ComputeCapacity{}
	add := func(site, kind, status string, n int) {
		k := key{site, kind}
		row := agg[k]
		if row == nil {
			row = &ComputeCapacity{Site: site, Kind: kind}
			agg[k] = row
		}
		row.Total += n
		switch strings.ToUpper(status) {
		case "BUSY":
			row.Busy += n
		case "IDLE":
			row.Idle += n
		}
	}
	for _, w := range workers {
		site := strings.TrimSpace(w.Site)
		if site == "" {
			site = "cloud"
		}
		var devs []string
		if w.Hardware != nil && w.Hardware.GPU != nil {
			for _, d := range w.Hardware.GPU.Devices {
				name := strings.TrimSpace(d.Name)
				if name == "" {
					name = "GPU"
				}
				devs = append(devs, name)
			}
		}
		if len(devs) == 0 {
			add(site, "CPU", w.Status, 1)
			continue
		}
		for _, name := range devs {
			add(site, name, w.Status, 1)
		}
	}
	out := ComputeSummary{Capacity: []ComputeCapacity{}, Sites: []ComputeSite{}, AsOf: now.UTC().Format(time.RFC3339)}
	for _, row := range agg {
		out.Capacity = append(out.Capacity, *row)
	}
	sort.Slice(out.Capacity, func(i, j int) bool {
		a, b := out.Capacity[i], out.Capacity[j]
		if a.Site != b.Site {
			return a.Site < b.Site
		}
		return a.Kind < b.Kind
	})
	seen := map[string]bool{}
	for _, s := range sites {
		if s.Site == "" || seen[s.Site] {
			continue
		}
		seen[s.Site] = true
		out.Sites = append(out.Sites, ComputeSite{Site: s.Site, OK: s.OK})
	}
	sort.Slice(out.Sites, func(i, j int) bool { return out.Sites[i].Site < out.Sites[j].Site })
	return out
}

func computeFederatorURL() string {
	if v := strings.TrimSpace(os.Getenv(computeFederatorEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return computeFederatorDefault
}

// fetchComputeSummary does the one upstream read: resolve the principal,
// mint its read-only bridge bearer, list the federated workers, aggregate.
func fetchComputeSummary(ctx context.Context) (ComputeSummary, error) {
	email := strings.TrimSpace(os.Getenv(computeSummaryAsEnv))
	if email == "" {
		email = computeSummaryAsDefault
	}
	u, err := computeSummaryUser(email)
	if err != nil || u.ID == "" {
		return ComputeSummary{}, fmt.Errorf("compute summary principal %q not found", email)
	}
	if u.Status == "suspended" {
		return ComputeSummary{}, fmt.Errorf("compute summary principal %q is suspended", email)
	}
	bearer, _, _, err := common.IssueBridgeJWT(u.ID, u.Email, u.Role, "flowmesh", computeSummaryScopes, 2*time.Minute)
	if err != nil {
		return ComputeSummary{}, fmt.Errorf("mint flowmesh bearer: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, computeUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, computeFederatorURL()+"/api/v1/workers?shape=full", nil)
	if err != nil {
		return ComputeSummary{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ComputeSummary{}, fmt.Errorf("federator unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, computeMaxBody))
	if err != nil {
		return ComputeSummary{}, fmt.Errorf("federator read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ComputeSummary{}, fmt.Errorf("federator HTTP %d", resp.StatusCode)
	}
	// ?shape=full is {items, sites}. A bare array means the path fell through
	// to a non-federated passthrough (one host only); counts are still counts,
	// but no site is claimed to have answered.
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var items []fmFleetWorker
		if err := json.Unmarshal(body, &items); err != nil {
			return ComputeSummary{}, fmt.Errorf("federator body: %w", err)
		}
		return computeSummaryFrom(items, nil, time.Now()), nil
	}
	var full struct {
		Items []fmFleetWorker `json:"items"`
		Sites []fmFleetSite   `json:"sites"`
	}
	if err := json.Unmarshal(body, &full); err != nil {
		return ComputeSummary{}, fmt.Errorf("federator body: %w", err)
	}
	return computeSummaryFrom(full.Items, full.Sites, time.Now()), nil
}

// ── cache + single-flight ────────────────────────────────────────────────────

type computeSummaryCall struct {
	done chan struct{}
	res  ComputeSummary
	err  error
}

var (
	computeMu       sync.Mutex
	computeCached   *ComputeSummary
	computeCacheExp time.Time
	computeErr      error
	computeErrExp   time.Time
	computeInflight *computeSummaryCall
)

// resetComputeSummaryCache clears the cache (tests).
func resetComputeSummaryCache() {
	computeMu.Lock()
	computeCached, computeErr, computeInflight = nil, nil, nil
	computeCacheExp, computeErrExp = time.Time{}, time.Time{}
	computeMu.Unlock()
}

// computeSummaryCached serves the cached summary, or joins / starts the one
// upstream read. The read runs detached from any single caller's context so
// one client hanging up does not fail everyone waiting on the same call.
func computeSummaryCached(ctx context.Context) (ComputeSummary, error) {
	computeMu.Lock()
	now := time.Now()
	if computeCached != nil && now.Before(computeCacheExp) {
		s := *computeCached
		computeMu.Unlock()
		return s, nil
	}
	if computeErr != nil && now.Before(computeErrExp) {
		err := computeErr
		computeMu.Unlock()
		return ComputeSummary{}, err
	}
	call := computeInflight
	if call == nil {
		call = &computeSummaryCall{done: make(chan struct{})}
		computeInflight = call
		go func() {
			res, err := fetchComputeSummary(context.Background())
			computeMu.Lock()
			call.res, call.err = res, err
			if err == nil {
				computeCached, computeCacheExp = &res, time.Now().Add(computeSummaryTTL)
				computeErr = nil
			} else {
				computeErr, computeErrExp = err, time.Now().Add(computeSummaryFailTTL)
			}
			if computeInflight == call {
				computeInflight = nil
			}
			computeMu.Unlock()
			close(call.done)
		}()
	}
	computeMu.Unlock()
	select {
	case <-call.done:
		return call.res, call.err
	case <-ctx.Done():
		return ComputeSummary{}, ctx.Err()
	}
}

// MeCompute — GET /me/compute
func MeCompute(c *gin.Context) {
	if _, okk := currentUserID(c); !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	s, err := computeSummaryCached(ginReqCtx(c))
	if err != nil {
		// The reason stays in the log: it can name the principal or the host.
		if !errors.Is(err, context.Canceled) {
			log.Printf("[me-compute] summary unavailable: %v", err)
		}
		fail(c, http.StatusServiceUnavailable, 1503, computeUnavailableMsg)
		return
	}
	ok(c, "ok", s)
}
