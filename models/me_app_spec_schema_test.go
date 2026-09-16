package models

// me_app_specs EXISTS ALREADY, and this struct has to match it.
//
// The table was created by an earlier implementation whose Go side was later
// deleted. The table outlived its code — still holding rows, while the
// scheduler's _echo_app_spec went on POSTing into a route that no longer
// existed. So "the type is not in the codebase" did NOT mean "the table is not
// in the database", and I read the first as the second.
//
// Declaring the conventional surrogate key here:
//
//	ID uint `gorm:"primaryKey"`
//
// makes AutoMigrate issue
//
//	ALTER TABLE me_app_specs ADD `id` bigint unsigned AUTO_INCREMENT,
//	                         ADD PRIMARY KEY (`id`)
//
// against a table that already has PRIMARY KEY (user_sub, app). MySQL answers
// 1068 "Multiple primary key defined", AutoMigrate returns the error, and
// identity refuses to start. That shipped as v0.5.382 and crash-looped the new
// pod (2026-09-16); the previous ReplicaSet kept serving, which is the only
// reason it was a degraded rollout and not an outage.
//
// These assertions are cheap and they run without a database — which is the
// point, because the DB-backed tests skip unless TEST_MYSQL_DSN is set and so
// none of them saw this.

import (
	"reflect"
	"strings"
	"testing"
)

func specTag(t *testing.T, field string) string {
	t.Helper()
	f, ok := reflect.TypeOf(MeAppSpec{}).FieldByName(field)
	if !ok {
		t.Fatalf("MeAppSpec has no field %q", field)
	}
	return f.Tag.Get("gorm")
}

// The live table's key. A surrogate id cannot be added beside it.
func TestMeAppSpecKeysOnUserSubAndApp(t *testing.T) {
	if _, hasID := reflect.TypeOf(MeAppSpec{}).FieldByName("ID"); hasID {
		t.Error("MeAppSpec declares an ID field. me_app_specs already has " +
			"PRIMARY KEY (user_sub, app), so AutoMigrate will try to ADD a second " +
			"primary key, MySQL will answer 1068, and identity will not boot.")
	}
	for _, f := range []string{"UserSub", "App"} {
		if !strings.Contains(specTag(t, f), "primaryKey") {
			t.Errorf("%s is not part of the primary key; the composite key on disk is "+
				"(user_sub, app) and the model must match it", f)
		}
	}
}

// A narrower column type is a silent data-loss migration: AutoMigrate will
// happily ALTER a live LONGTEXT down to MEDIUMTEXT. These hold whole spec files.
func TestMeAppSpecTextColumnsAreNotNarrowed(t *testing.T) {
	for _, f := range []string{"SpecYAML", "UIFiles"} {
		tag := specTag(t, f)
		if !strings.Contains(tag, "type:longtext") {
			t.Errorf("%s is not declared longtext (%q). The live column is LONGTEXT; "+
				"anything narrower makes AutoMigrate shrink a column that holds "+
				"entire spec files.", f, tag)
		}
	}
}

// Widening a column is not free either — it rewrites a table other code is
// reading. Match what is on disk so migration is a no-op.
func TestMeAppSpecColumnSizesMatchTheLiveTable(t *testing.T) {
	for field, want := range map[string]string{"UserSub": "size:36", "App": "size:64"} {
		if tag := specTag(t, field); !strings.Contains(tag, want) {
			t.Errorf("%s declares %q, but the live column is %s — AutoMigrate would "+
				"ALTER a table it does not need to touch", field, tag, want)
		}
	}
}

// Every field must name its column explicitly: the table predates this struct,
// so GORM's name inference is not authoritative here.
func TestMeAppSpecNamesEveryColumn(t *testing.T) {
	ty := reflect.TypeOf(MeAppSpec{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if !strings.Contains(f.Tag.Get("gorm"), "column:") {
			t.Errorf("field %s names no column; the table predates this struct and "+
				"inferred names may not match it", f.Name)
		}
	}
	if (MeAppSpec{}).TableName() != "me_app_specs" {
		t.Errorf("TableName is %q, not me_app_specs", (MeAppSpec{}).TableName())
	}
}
