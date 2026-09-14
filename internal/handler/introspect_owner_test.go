package handler

// A PAT is a claim about a principal. Both introspection paths used to
// validate the token and never the principal, so a token stayed Active after
// its owner was deleted or suspended:
//
//   - introspectLegacyLQA keys on token_hash alone and treated the tbl_user
//     lookup as enrichment -> a deleted owner yielded Active:true with the
//     token's scopes intact and an empty role.
//   - introspectNative had the same shape. Delete happens to take native
//     tokens with it (AdminUsersDelete), but SUSPEND did not: a suspended
//     user kept full API access while the login path refused them 403.
//
// The positive cases here matter as much as the negative ones -- this is the
// hottest path in the estate and over-rejecting breaks all PAT auth.
//
//   TEST_MYSQL_DSN='root:testpass@tcp(127.0.0.1:3306)/' \
//     go test ./internal/handler -run IntrospectOwner -v

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"lumid_identity/models"
)

func TestIntrospectOwnerRejection(t *testing.T) {
	cases := []struct {
		name       string
		missing    bool
		status     string
		wantReject bool
		wantReason string
	}{
		{"active owner passes", false, "active", false, ""},
		{"empty status treated as active", false, "", false, ""},
		// pending users can log in (auth.go checks only "suspended"), so their
		// tokens must keep working -- rejecting them would be a silent
		// behaviour change on a path nobody asked us to tighten.
		{"pending owner passes", false, "pending", false, ""},
		{"suspended owner rejected", false, "suspended", true, "user suspended"},
		{"missing owner rejected", true, "active", true, "user not found"},
		{"missing beats status", true, "suspended", true, "user not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := ownerRejection(tc.missing, tc.status)
			if got != tc.wantReject {
				t.Fatalf("reject = %v, want %v (missing=%v status=%q)",
					got, tc.wantReject, tc.missing, tc.status)
			}
			if got && reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// --- integration: prove the CALL SITES use the rule, not just the helper ---
//
// A passing unit test on ownerRejection would be satisfied by a function
// nothing calls, so these drive introspectNative / introspectLegacyLQA against
// real rows and assert on Active.

func TestIntrospectOwnerNativeEndToEnd(t *testing.T) {
	idb, _ := setupLegacyDeleteDBs(t)

	const uid = "aaaaaaaa-0000-0000-0000-00000000000a"
	const tok = "lm_pat_ownercheck_native"
	sum := sha256.Sum256([]byte(tok))
	if err := idb.Create(&models.User{
		ID: uid, Email: "owner-native@yao.lu", Name: "owner", Role: "user", Status: "active",
	}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := idb.Create(&models.Token{
		ID: "tok-native-1", UserID: uid, Prefix: "lm_pat", Hash: hex.EncodeToString(sum[:]),
		HashAlg: "sha256", Name: "owner-check", Scopes: "lumilake:jobs:read",
	}).Error; err != nil {
		t.Fatalf("seed token: %v", err)
	}

	// 1. Active owner -> the token must work. Guards against over-rejection.
	if r := introspectNative(tok); r == nil || !r.Active {
		t.Fatalf("active owner: want Active, got %+v", r)
	}

	// 2. Suspended owner -> refused. Previously this kept full API access
	//    while the login path returned 403.
	idb.Model(&models.User{}).Where("id = ?", uid).Update("status", "suspended")
	if r := introspectNative(tok); r == nil || r.Active {
		t.Errorf("suspended owner: want inactive, got %+v", r)
	} else if r.Reason != "user suspended" {
		t.Errorf("reason = %q, want \"user suspended\"", r.Reason)
	}

	// 3. Owner gone entirely -> refused.
	idb.Where("id = ?", uid).Delete(&models.User{})
	if r := introspectNative(tok); r == nil || r.Active {
		t.Errorf("deleted owner: want inactive, got %+v", r)
	} else if r.Reason != "user not found" {
		t.Errorf("reason = %q, want \"user not found\"", r.Reason)
	}
}

func TestIntrospectOwnerLegacyEndToEnd(t *testing.T) {
	_, ldb := setupLegacyDeleteDBs(t)

	const tok = "rm_pat_ownercheck_legacy"
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])
	if err := ldb.Exec(`INSERT INTO tbl_user (id, email, username, password_hash, role, status,
		invitation_code, create_time, update_time)
		VALUES (7001, 'owner-legacy@yao.lu', 'ol', 'h', 'user', 'active', '', 0, 0)`).Error; err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	if err := ldb.Exec(`INSERT INTO tbl_rm_personal_access_token
		(user_id, token_hash, scopes, expires_at, revoked_at, name)
		VALUES (7001, ?, 'flowmesh:workflows:write', 0, 0, 'legacy-owner-check')`, hash).Error; err != nil {
		t.Fatalf("seed legacy pat: %v", err)
	}

	if r := introspectLegacyLQA(tok); r == nil || !r.Active {
		t.Fatalf("active legacy owner: want Active, got %+v", r)
	}

	ldb.Exec(`UPDATE tbl_user SET status = 'suspended' WHERE id = 7001`)
	if r := introspectLegacyLQA(tok); r == nil || r.Active {
		t.Errorf("suspended legacy owner: want inactive, got %+v", r)
	}

	// The orphan: the row the delete fix removes, reachable by any other route.
	ldb.Exec(`DELETE FROM tbl_user WHERE id = 7001`)
	r := introspectLegacyLQA(tok)
	if r == nil || r.Active {
		t.Errorf("orphaned legacy PAT: want inactive, got %+v", r)
	} else if r.Reason != "user not found" {
		t.Errorf("reason = %q, want \"user not found\"", r.Reason)
	}
}
