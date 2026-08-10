package handler

import (
	"testing"
	"time"
)

func TestFingerprintInfoForLabel_RotatesAcrossEpochs(t *testing.T) {
	origOverrides, origRotate := fieldRelayFingerprintOverrides, fieldRelayFingerprintRotate
	defer func() {
		fieldRelayFingerprintOverrides, fieldRelayFingerprintRotate = origOverrides, origRotate
	}()
	fieldRelayFingerprintOverrides = map[string]string{}
	fieldRelayFingerprintRotate = time.Hour

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first := fingerprintInfoForLabel("test-rotation-box", base)

	// Still inside the same 1h bucket: must not rotate.
	if same := fingerprintInfoForLabel("test-rotation-box", base.Add(30*time.Minute)); same.PackageVersion != first.PackageVersion {
		t.Fatalf("fingerprint changed within the same epoch: %+v vs %+v", first, same)
	}

	// Past the rotation window: the derived version must be free to change.
	// (Not guaranteed to differ — the hash could land on the same pool entry —
	// but RotatesAt must always advance to the new bucket's boundary.)
	rotated := fingerprintInfoForLabel("test-rotation-box", base.Add(2*time.Hour))
	if first.RotatesAt == nil || rotated.RotatesAt == nil {
		t.Fatalf("expected RotatesAt to be set for a non-override label, got first=%v rotated=%v", first.RotatesAt, rotated.RotatesAt)
	}
	if !rotated.RotatesAt.After(*first.RotatesAt) {
		t.Fatalf("expected RotatesAt to advance after the rotation window, got %v then %v", *first.RotatesAt, *rotated.RotatesAt)
	}
}

func TestFingerprintInfoForLabel_OverrideSurvivesRotation(t *testing.T) {
	origOverrides, origRotate := fieldRelayFingerprintOverrides, fieldRelayFingerprintRotate
	defer func() {
		fieldRelayFingerprintOverrides, fieldRelayFingerprintRotate = origOverrides, origRotate
	}()
	fieldRelayFingerprintOverrides = map[string]string{"test-override-box": "9.9.9"}
	fieldRelayFingerprintRotate = time.Hour

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first := fingerprintInfoForLabel("test-override-box", base)
	if !first.Override || first.PackageVersion != "9.9.9" {
		t.Fatalf("expected an override hit, got %+v", first)
	}
	if first.RotatesAt != nil {
		t.Fatalf("expected an override to report no rotation time, got %v", *first.RotatesAt)
	}

	rotated := fingerprintInfoForLabel("test-override-box", base.Add(2*time.Hour))
	if !rotated.Override || rotated.PackageVersion != "9.9.9" {
		t.Fatalf("expected the override to survive rotation unchanged, got %+v", rotated)
	}
}

func TestParseFieldRelayFingerprints(t *testing.T) {
	got := parseFieldRelayFingerprints("denmark=0.99.0, chicago=1.0.0,, malformed,nyc=")
	want := map[string]string{"denmark": "0.99.0", "chicago": "1.0.0"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %s: got %q, want %q", k, got[k], v)
		}
	}
}
