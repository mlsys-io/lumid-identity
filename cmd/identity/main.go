package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/internal/handler"
	"lumid_identity/models"
)

func main() {
	cfgPath := flag.String("c", "configs/identity.yaml", "path to config yaml")
	// One-shot mode for the monthly CronJob: move idle sessions' recording
	// blobs to the cold tier, then exit. See handler/claude_sessions_cold_sweep.go.
	sweepCold := flag.Bool("sweep-cold-sessions", false, "move idle Claude session blobs to the cold tier and exit")
	coldAfter := flag.Duration("cold-after", 30*24*time.Hour, "with -sweep-cold-sessions: idle age that makes a session cold")
	sweepWorkers := flag.Int("sweep-workers", 16, "with -sweep-cold-sessions: sessions moved concurrently")
	sweepLimit := flag.Int("sweep-limit", 0, "with -sweep-cold-sessions: max sessions this run (0 = all)")
	sweepDryRun := flag.Bool("sweep-dry-run", false, "with -sweep-cold-sessions: count only")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if err := common.OpenDB(cfg); err != nil {
		log.Fatalf("open db: %v", err)
	}
	if *sweepCold {
		// Deliberately before AutoMigrate and every loop below: a batch run
		// must not migrate the schema or start the server's background work.
		common.InitBlobStore()
		if _, err := handler.SweepColdSessions(handler.ColdSweepOptions{
			ColdAfter: *coldAfter, Workers: *sweepWorkers, Limit: *sweepLimit, DryRun: *sweepDryRun,
		}); err != nil {
			log.Printf("cold sweep FAILED: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := models.AutoMigrate(common.DB); err != nil {
		log.Fatalf("automigrate: %v", err)
	}
	// Seeds the "default" Claude pool and backfills every pre-existing
	// account/user into it. Idempotent (IF-NOT-EXISTS / INSERT-IGNORE
	// throughout) — safe on every pod boot, every replica. This service is
	// fully self-deploying with no operator migration step, so this backfill
	// MUST be code, not a migrations/*.sql file nobody runs by hand.
	if err := handler.EnsureDefaultClaudePool(common.DB); err != nil {
		log.Fatalf("seed default claude pool: %v", err)
	}
	if err := common.OpenRedis(cfg, 30*time.Second); err != nil {
		// Not fatal: login/introspection don't need Redis and the client reconnects lazily.
		log.Printf("WARN redis unreachable at startup (%v); continuing degraded — OTP/cool-downs fail until it returns, rate limits fail open", err)
	}
	if err := common.LoadKeys(cfg); err != nil {
		log.Fatalf("load signing keys: %v", err)
	}

	// Session blob offloading: store LONGBLOB gzip blobs in S3 when configured.
	common.InitBlobStore()

	// Proactively refresh Claude OAuth pool tokens every 45min.
	handler.StartTokenRefreshLoop()

	// Keep pool account quota snapshots warm so leases stay on the fast cache
	// path (never re-probe inline, which serialized fan-out bursts → spurious 503).
	handler.StartSnapshotRefreshLoop()
	handler.StartAssignmentReclaimLoop()

	// Sweep expired auto-minted claude-sandbox PATs hourly.
	handler.StartClaudeSandboxPATSweep()

	// Delete long-expired rows from `sessions`. Nothing pruned that table: it had
	// reached 238,758 rows of which 238,732 were expired, i.e. 26 live sessions
	// inside 161 MB, on a 2Gi PVC that had hit 95% full. This IS the auth
	// authority's database.
	handler.StartSessionReclaimLoop()
	// Retention for the interaction-event table, started with the writer.
	handler.StartInteractionReclaimLoop()

	// Drop client-fingerprint observations too old for any window to read.
	handler.StartClaudeFingerprintGC()

	// Archive cold rows from the append-only growth tables to object storage,
	// then delete them. This DB filled its volume on 2026-08-17 and again on
	// 2026-09-15 (100%, auth down estate-wide); the drivers grow ~14 MB/day and
	// nothing bounded them. No-ops unless the blobstore is configured.
	handler.StartRetentionSweep()

	if cfg.App.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	handler.Register(r)

	addr := ":" + itoa(cfg.App.Port)
	log.Printf("lumid-identity listening on %s (issuer=%s, active_kid=%s, legacy_shadow=%v)",
		addr, cfg.App.Issuer, common.Keys.Active().Kid, cfg.Legacy.Enabled)
	if err := r.Run(addr); err != nil {
		log.Fatalf("run: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [11]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
