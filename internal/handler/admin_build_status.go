package handler

import (
	"time"

	"github.com/gin-gonic/gin"
)

// GET /admin/build-status — super-admin dashboard tile.
//
// Stub. Returns an empty list until P5.x wires up build-from-elsewhere
// (GitHub Actions → GHCR → docker compose pull on nimi0). Once we have
// repository_dispatch + ghcr digests + per-service rollout state, this
// is where the dashboard reads from.
//
// Future shape (already enshrined here so the React tile can be wired):
//   {
//     services: [
//       { service, current_image, current_tag, last_build_at,
//         pending_update: bool, latest_tag, ci_run_url }
//     ]
//   }

func AdminBuildStatus(c *gin.Context) {
	ok(c, "ok", gin.H{
		"services":    []any{},
		"generated_at": time.Now().UTC(),
		"note":        "P5 build/deploy separation not yet wired — placeholder response",
	})
}
