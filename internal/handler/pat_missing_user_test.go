package handler

import (
	"errors"
	"os"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// A PAT minted for a user that does not exist never introspects active, so it
// is a credential row that can only produce 401s downstream. Refuse it.
func TestMintPATForUserRefusesMissingUser(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping PAT mint integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Token{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db

	ghost := "00000000-0000-0000-0000-0000000ghost"
	tok, row, err := mintPATForUser(ghost, "t", []string{"lqt:strategy"}, nil, "intent")
	if !errors.Is(err, errPATUserNotFound) || tok != "" || row != nil {
		t.Fatalf("mint for missing user = (%q, %v, %v), want errPATUserNotFound", tok, row, err)
	}
	var n int64
	db.Model(&models.Token{}).Where("user_id = ?", ghost).Count(&n)
	if n != 0 {
		t.Fatalf("%d token rows persisted for a missing user", n)
	}
}
