package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// GET /admin/backup-status — super-admin dashboard tile.
//
// Like cert-expiry: proxy to Prometheus rather than touching /nfss
// from the identity container. The textfile collector exposes
// `lumid_backup_last_success_timestamp_seconds{backup_job=...}` per
// job and `lumid_backup_verify_success` for the weekly restore-test.

func AdminBackupStatus(c *gin.Context) {
	promURL := os.Getenv("PROMETHEUS_URL")
	if promURL == "" {
		promURL = "http://host.docker.internal:9090"
	}

	tsByJob := promFloatByLabel(promURL,
		`lumid_backup_last_success_timestamp_seconds`, "backup_job")
	verifySuccess := promScalar(promURL, `lumid_backup_verify_success`)
	verifyTS := promScalar(promURL, `lumid_backup_verify_last_run_timestamp_seconds`)

	now := time.Now().UTC()
	type jobRow struct {
		Job      string    `json:"job"`
		LastRun  time.Time `json:"last_run"`
		AgeHours int       `json:"age_hours"`
		Healthy  bool      `json:"healthy"` // last_run < 26h
	}
	jobs := make([]jobRow, 0, len(tsByJob))
	for j, ts := range tsByJob {
		t := time.Unix(int64(ts), 0).UTC()
		age := int(now.Sub(t).Hours())
		jobs = append(jobs, jobRow{
			Job:      j,
			LastRun:  t,
			AgeHours: age,
			Healthy:  age < 26,
		})
	}

	verifyHealthy := verifySuccess == 1
	var verifyAt *time.Time
	if verifyTS > 0 {
		t := time.Unix(int64(verifyTS), 0).UTC()
		verifyAt = &t
	}

	ok(c, "ok", gin.H{
		"jobs": jobs,
		"verify": gin.H{
			"healthy":  verifyHealthy,
			"last_run": verifyAt,
		},
		"checked_at": now,
	})
}

// promFloatByLabel runs an instant query and returns label_value → metric_value.
func promFloatByLabel(promURL, query, label string) map[string]float64 {
	q := url.Values{}
	q.Set("query", query)
	resp, err := http.Get(promURL + "/api/v1/query?" + q.Encode())
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var pr struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil
	}
	out := map[string]float64{}
	for _, r := range pr.Data.Result {
		if len(r.Value) < 2 {
			continue
		}
		s, _ := r.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out[r.Metric[label]] = v
	}
	return out
}

// promScalar runs an instant query and returns the single sample's value.
// Returns 0 if no samples.
func promScalar(promURL, query string) float64 {
	q := url.Values{}
	q.Set("query", query)
	resp, err := http.Get(promURL + "/api/v1/query?" + q.Encode())
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var pr struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return 0
	}
	if len(pr.Data.Result) == 0 || len(pr.Data.Result[0].Value) < 2 {
		return 0
	}
	s, _ := pr.Data.Result[0].Value[1].(string)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
