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

func TestCheckUsername(t *testing.T) {
	t.Setenv("RESERVED_USERNAMES", "minhao, zhengyuan")
	for _, c := range []struct {
		in      string
		admin   bool
		want    string
		wantErr error
	}{
		{"Zhengyuan", true, "zhengyuan", nil},
		{"zhengyuan", false, "", errUsernameReserved},
		{"root", false, "", errUsernameReserved},
		{"ab", false, "ab", nil},
		{"a", false, "", errUsernameInvalid},
		{"1abc", false, "", errUsernameInvalid},
		{"has space", false, "", errUsernameInvalid},
		{"x" + string(make([]byte, 0)) + "abcdefghijabcdefghijabcdefghijab", false, "", errUsernameInvalid},
		{"good_name-1", false, "good_name-1", nil},
	} {
		got, err := checkUsername(c.in, c.admin)
		if !errors.Is(err, c.wantErr) || got != c.want {
			t.Errorf("checkUsername(%q, %v) = (%q, %v), want (%q, %v)", c.in, c.admin, got, err, c.want, c.wantErr)
		}
	}
}

func TestSuggestUsername(t *testing.T) {
	for in, want := range map[string]string{
		"suzhengy@comp.nus.edu.sg": "suzhengy",
		"Su.Zheng+lab@x.org":       "suzheng",
		"9fred@x.org":              "fred",
		"x@y.z":                    "",
		"ctree4113@gmail.com":      "ctree4113",
		"admin@lum.id":             "",
	} {
		if got := suggestUsername(in); got != want {
			t.Errorf("suggestUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

// Integration: uid assigned once from 20000 and kept across renames; a taken name and a name someone else held
// before are refused; history records every change.
func TestSetUsernameLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping username integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.User{}, &models.UsernameChange{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	a := models.User{ID: "un-test-a", Email: "un-a@example.com"}
	b := models.User{ID: "un-test-b", Email: "un-b@example.com"}
	db.Where("id IN ?", []string{a.ID, b.ID}).Delete(&models.User{})
	db.Where("user_id IN ?", []string{a.ID, b.ID}).Delete(&models.UsernameChange{})
	db.Create(&a)
	db.Create(&b)
	t.Cleanup(func() {
		db.Where("id IN ?", []string{a.ID, b.ID}).Delete(&models.User{})
		db.Where("user_id IN ?", []string{a.ID, b.ID}).Delete(&models.UsernameChange{})
	})

	ua, err := setUsername(a.ID, "untesta", "")
	if err != nil || ua.PosixUID == nil || *ua.PosixUID < firstUID {
		t.Fatalf("first set: %+v %v", ua, err)
	}
	uid := *ua.PosixUID
	if _, err := setUsername(b.ID, "untesta", ""); !errors.Is(err, errUsernameTaken) {
		t.Fatalf("taking a used name: %v", err)
	}
	ua, err = setUsername(a.ID, "untesta2", "")
	if err != nil || *ua.PosixUID != uid {
		t.Fatalf("rename kept uid? %+v %v", ua, err)
	}
	if _, err := setUsername(b.ID, "untesta", ""); !errors.Is(err, errUsernameTaken) {
		t.Fatalf("a name someone held before must stay theirs: %v", err)
	}
	ub, err := setUsername(b.ID, "untestb", "")
	if err != nil || *ub.PosixUID == uid {
		t.Fatalf("second person gets a different uid: %+v %v", ub, err)
	}
	var n int64
	db.Model(&models.UsernameChange{}).Where("user_id = ?", a.ID).Count(&n)
	if n != 2 {
		t.Fatalf("history rows for a = %d, want 2", n)
	}
}

// The login name travels as posix_username; `username` stays the display name in every response that has it.
func TestPosixUsernameNeverTheDisplayName(t *testing.T) {
	login := "minhao"
	u := models.User{ID: "x", Email: "x@y.z", Name: "Curious Learner", Username: &login}
	h := userInfoFromModel(&u)
	if h["username"] != "Curious Learner" || h["posix_username"] != &login {
		t.Fatalf("userInfoFromModel = %v", h)
	}
	r := IntrospectResponse{Username: "Curious Learner", PosixUsername: &login}
	if r.Username == *r.PosixUsername {
		t.Fatal("display name leaked into posix_username")
	}
}
