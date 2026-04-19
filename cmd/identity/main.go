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
