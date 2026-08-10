package handler

// Field-relay SDK fingerprint — read-only mirror of claude-proxy's rotation logic
// (deploy_infra/k8s-lift/claude-proxy/app/main.go), so the /code field-box panel can show
// the CURRENT anthropic-sdk-typescript fingerprint claude-proxy is attaching to each field
// box's egress, without identity calling claude-proxy over the network for a value that's
// pure computation.
//
// Same duplication tradeoff as `fieldRelays` above (admin_claude_quota.go): this only
// matches claude-proxy's actual headers if LUMID_CLAUDE_FIELD_RELAY_FINGERPRINTS and
// LUMID_CLAUDE_FIELD_RELAY_FINGERPRINT_ROTATE are kept identical on both deployments. If
// they drift, the chip silently shows a stale/wrong value — same risk already accepted for
// fieldRelays, not new here.

import (
	"crypto/sha256"
	"os"
	"strconv"
	"strings"
	"time"
)

// stainlessVersionPool mirrors claude-proxy's pool exactly — must stay byte-identical or
// the derived version for a given (label, epoch) diverges between the two services.
var stainlessVersionPool = []string{"0.108.2", "0.110.0", "0.112.1", "0.114.3", "0.116.0"}

var (
	fieldRelayFingerprintOverrides = parseFieldRelayFingerprints(os.Getenv("LUMID_CLAUDE_FIELD_RELAY_FINGERPRINTS"))
	fieldRelayFingerprintRotate    = envDurationOr("LUMID_CLAUDE_FIELD_RELAY_FINGERPRINT_ROTATE", 30*24*time.Hour)
)

// fieldFingerprintInfo is the JSON shape returned to the /code panel.
type fieldFingerprintInfo struct {
	UserAgent      string `json:"user_agent"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Runtime        string `json:"runtime"`
	PackageVersion string `json:"package_version"`
	Override       bool   `json:"override"`
	// RotatesAt is nil when Override is true (an override never rotates) — a
	// pointer, not a zero time.Time, because encoding/json's omitempty does NOT
	// treat a zero-value struct as empty; only nil/zero scalars are omitted.
	RotatesAt *time.Time `json:"rotates_at,omitempty"`
}

func parseFieldRelayFingerprints(spec string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		label, ver := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if label != "" && ver != "" {
			out[label] = ver
		}
	}
	return out
}

// envDurationOr parses a Go duration string from the environment, falling back to def on
// an empty or unparsable value.
func envDurationOr(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// fingerprintEpoch buckets wall-clock time into fieldRelayFingerprintRotate-wide windows —
// identical formula to claude-proxy's, so both services land on the same bucket for the same
// clock without any shared state.
func fingerprintEpoch(now time.Time) int64 {
	period := int64(fieldRelayFingerprintRotate / time.Second)
	if period <= 0 {
		return 0
	}
	return now.Unix() / period
}

// fingerprintInfoForLabel derives the current fingerprint for a field-box label, mirroring
// claude-proxy's fingerprintForLabel. Unlike claude-proxy this is NOT cached — this handler
// runs once per admin page load, not per egress request, so the recompute cost is irrelevant
// and skipping the cache avoids a second mutex-guarded map to keep in sync for no benefit.
func fingerprintInfoForLabel(label string, now time.Time) fieldFingerprintInfo {
	epoch := fingerprintEpoch(now)
	pkgVersion := fieldRelayFingerprintOverrides[label]
	override := pkgVersion != ""
	if !override {
		h := sha256.Sum256([]byte(label + ":" + strconv.FormatInt(epoch, 10)))
		pkgVersion = stainlessVersionPool[int(h[0])%len(stainlessVersionPool)]
	}
	info := fieldFingerprintInfo{
		UserAgent:      "Anthropic/JS " + pkgVersion,
		OS:             "Linux",
		Arch:           "x64",
		Runtime:        "node",
		PackageVersion: pkgVersion,
		Override:       override,
	}
	if !override {
		period := fieldRelayFingerprintRotate
		if period <= 0 {
			period = 30 * 24 * time.Hour
		}
		rotatesAt := time.Unix((epoch+1)*int64(period/time.Second), 0).UTC()
		info.RotatesAt = &rotatesAt
	}
	return info
}
