package main

import (
	"flag"
	"log"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/internal/handler"
	"lumid_identity/models"
)

func main() {
	cfgPath := flag.String("c", "configs/identity.yaml", "path to config yaml")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if err := common.OpenDB(cfg); err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := models.AutoMigrate(common.DB); err != nil {
		log.Fatalf("automigrate: %v", err)
	}
	if err := common.OpenRedis(cfg); err != nil {
		log.Fatalf("open redis: %v", err)
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
