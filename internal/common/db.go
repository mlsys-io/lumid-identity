package common

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"lumid_identity/internal/config"
)

var DB *gorm.DB

// LegacyDB points at trading_community during shadow phase so
// introspect can mirror LQA without a data copy. nil after cutover.
var LegacyDB *gorm.DB

func OpenDB(c *config.Config) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
		c.MySQL.User, c.MySQL.Password, c.MySQL.Host, c.MySQL.Port, c.MySQL.Database)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return fmt.Errorf("open identity db: %w", err)
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
