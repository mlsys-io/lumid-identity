package common

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"lumid_identity/internal/config"
)

var DB *gorm.DB

// ClaudeOAuthSecretKey is the app_secrets key name used by the Studio
// "Connect Claude" modal (claude_verify.go). Shared constant so the
// admin quota poller and the verify handler always agree on the name.
const ClaudeOAuthSecretKey = "CLAUDE_CODE_OAUTH_TOKEN"

// LegacyDB points at trading_community during shadow phase so
// introspect can mirror LQA without a data copy. nil after cutover.
var LegacyDB *gorm.DB

func OpenDB(c *config.Config) error {
	// Fail fast instead of piling up: a 3 s dial timeout and 10 s read/write timeouts bound how long
	// a request can sit on a dead or stalled MySQL. With none (the driver default) every request
	// during an outage holds its goroutine + memory until the OS gives up on the TCP connect, and
	// when MySQL returns the whole backlog lands at once. On 2026-10-26 that recovery burst pushed
	// svc-lthl8-q9wmb into a node-wide OOM (kernel killed identity) 3 min after a planned restart.
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&timeout=3s&readTimeout=10s&writeTimeout=10s",
		c.MySQL.User, c.MySQL.Password, c.MySQL.Host, c.MySQL.Port, c.MySQL.Database)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return fmt.Errorf("open identity db: %w", err)
	}
	// Bound the pool so a burst cannot open hundreds of connections (2 replicas x 80 stays well under
	// the shared instance's max_connections=500), and recycle connections so a MySQL restart does not
	// leave a pool of dead ones behind.
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(80)
		sqlDB.SetMaxIdleConns(20)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
		sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	}
	DB = db

	if c.Legacy.Enabled && c.Legacy.DSN != "" {
		ldb, err := gorm.Open(mysql.Open(c.Legacy.DSN), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Warn),
		})
		if err != nil {
			return fmt.Errorf("open legacy lqa db: %w", err)
		}
		LegacyDB = ldb
	}
	return nil
}
