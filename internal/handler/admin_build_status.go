package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
)

// GET /admin/build-status — super-admin dashboard tile.
//
// Reads the snapshot at /var/lib/lumid-build-state/build-status.json
// (refreshed every 5 min by collect-build-status.sh). The snapshot
// covers every service in the auto-build registry: live container
// state, image creation date + size, last-built git sha, and the
// timestamp of the last auto-build cron run.
//
// If the snapshot is missing (cron hasn't run yet, or volume isn't
// mounted), returns an empty list with a clear note instead of 500.

type buildServiceRow struct {
	Service          string `json:"service"`
	Container        string `json:"container"`
	ContainerStatus  string `json:"container_status"`
	ContainerStarted string `json:"container_started"`
	Image            string `json:"image"`
	ImageID          string `json:"image_id"`
	ImageCreated     string `json:"image_created"`
	ImageSize        string `json:"image_size"`
	LastBuiltSha     string `json:"last_built_sha"`
	LastBuiltAt      string `json:"last_built_at"`
}

type buildStatusSnapshot struct {
	GeneratedAt string             `json:"generated_at"`
	Services    []buildServiceRow  `json:"services"`
}

func AdminBuildStatus(c *gin.Context) {
	const snapshotPath = "/var/lib/lumid-build-state/build-status.json"

	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		ok(c, "ok", gin.H{
			"services":      []any{},
			"generated_at":  time.Now().UTC(),
			"snapshot_age":  -1,
			"note":          "snapshot not yet available; collect-build-status.sh hasn't run",
		})
		return
	}

	var snap buildStatusSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		fail(c, http.StatusInternalServerError, 5001, "snapshot parse: "+err.Error())
		return
	}

	// Compute snapshot age in minutes for the dashboard's freshness chip
	ageMin := -1
	if snap.GeneratedAt != "" {
		if t, err := time.Parse(time.RFC3339, snap.GeneratedAt); err == nil {
			ageMin = int(time.Since(t).Minutes())
		}
	}

	// Sort services alphabetically so dashboard ordering is stable
	sort.Slice(snap.Services, func(i, j int) bool {
		return snap.Services[i].Service < snap.Services[j].Service
	})

	ok(c, "ok", gin.H{
		"services":     snap.Services,
		"generated_at": snap.GeneratedAt,
		"snapshot_age": ageMin,
	})
}
