package handler

// Phase D2 — per-tenant storage visibility.
//
// Lightweight directory walk over the tenant's apps + KG banks tree.
// Results cached for 5 minutes so a /me/storage refresh from the UI
// (or repeated polls from the scheduler) doesn't du-bomb the FS.
//
// Hard cap (defer new cycles when over) is a small follow-up — the
// scheduler can read this endpoint OR call a sibling helper. For
// dogfood we just surface the number so the UI can render a
// "X of Y GB used" tile.

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultStorageCapMB = 2048

type storageSnapshot struct {
	tenantSub  string
	usedBytes  int64
	measuredAt time.Time
	apps       int
	largest    string
}

var (
	storageCacheMu sync.Mutex
	storageCache   = map[string]storageSnapshot{}
)

func storageCapMB() int64 {
	if v := os.Getenv("LUMID_QUOTA_STORAGE_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultStorageCapMB
}

// measureTenantStorage walks the tenant tree and sums file sizes.
// Cached for 5 minutes per tenant. The walk is bounded by the tenant's
// own tree (≤ Tier-2 cap) so the worst case is ~2GB of stat() calls
// which completes in well under a second on warm cache.
func measureTenantStorage(userSub string) storageSnapshot {
	storageCacheMu.Lock()
	cached, ok := storageCache[userSub]
	storageCacheMu.Unlock()
	if ok && time.Since(cached.measuredAt) < 5*time.Minute {
		return cached
	}

	root := filepath.Join(operatorHome(), ".tenants", userSub)
	var (
		total int64
		apps  int
		// Largest single file — useful when the user is over and wants
		// to know what to clean up first.
		largest     string
		largestSize int64
	)
	tenantApps := filepath.Join(root, ".xp", "apps")
	if entries, err := os.ReadDir(tenantApps); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				apps++
			}
		}
	}
	// Walk the entire tenant root — apps + KG + lumilake state etc.
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		sz := info.Size()
		total += sz
		if sz > largestSize {
			largestSize = sz
			largest = path
		}
		return nil
	})

	snap := storageSnapshot{
		tenantSub:  userSub,
		usedBytes:  total,
		measuredAt: time.Now().UTC(),
		apps:       apps,
		largest:    largest,
	}
	storageCacheMu.Lock()
	storageCache[userSub] = snap
	storageCacheMu.Unlock()
	return snap
}

// MeStorage serves GET /api/v1/me/storage.
//
// {used_bytes, used_mb, cap_mb, fraction, apps, largest_path, measured_at}
// The UI shows "X of Y GB used" + a small warning when fraction > 0.8.
func MeStorage(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	snap := measureTenantStorage(userID)
	capMB := storageCapMB()
	usedMB := float64(snap.usedBytes) / (1024 * 1024)
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"used_bytes":   snap.usedBytes,
			"used_mb":      usedMB,
			"cap_mb":       capMB,
			"fraction":     usedMB / float64(capMB),
			"apps":         snap.apps,
			"largest_path": snap.largest,
			"measured_at":  snap.measuredAt.Format(time.RFC3339),
		},
	})
}
