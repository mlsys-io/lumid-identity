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

// GET /admin/cert-expiry — super-admin dashboard tile.
//
// Cert expiry would normally require reading /etc/letsencrypt — but
// that's root-owned and lumid-identity is a non-root container with
// no LE volume mounted. Instead we proxy to Prometheus, which already
// scrapes `probe_ssl_earliest_cert_expiry` via blackbox-tls. This
// keeps identity's surface narrow and makes one source of truth
// (the same number Grafana shows).
//
// The PROMETHEUS_URL env var defaults to the host-bound Prometheus
// at host.docker.internal:9090 (set in compose override).

func AdminCertExpiry(c *gin.Context) {
	promURL := os.Getenv("PROMETHEUS_URL")
	if promURL == "" {
		promURL = "http://host.docker.internal:9090"
	}

	q := url.Values{}
	q.Set("query", `probe_ssl_earliest_cert_expiry{job="blackbox-tls"}`)
	resp, err := http.Get(promURL + "/api/v1/query?" + q.Encode())
	if err != nil {
		fail(c, http.StatusBadGateway, 5001, "prometheus unreachable")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var pr struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		fail(c, http.StatusBadGateway, 5001, "prometheus returned malformed json")
		return
	}

	type certRow struct {
		Domain    string    `json:"domain"`
		ExpiresAt time.Time `json:"expires_at"`
		DaysLeft  int       `json:"days_left"`
	}
	now := time.Now().UTC()
	out := make([]certRow, 0, len(pr.Data.Result))
	for _, r := range pr.Data.Result {
		// instance is "lum.id:443"; strip the port for display.
		dom := r.Metric["instance"]
		for i := 0; i < len(dom); i++ {
			if dom[i] == ':' {
				dom = dom[:i]
				break
			}
		}
		// value is [unix_ts, "expiry_unix"]
		if len(r.Value) < 2 {
			continue
		}
		s, _ := r.Value[1].(string)
		expUnix, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		exp := time.Unix(int64(expUnix), 0).UTC()
		days := int(exp.Sub(now).Hours() / 24)
		out = append(out, certRow{
			Domain:    dom,
			ExpiresAt: exp,
			DaysLeft:  days,
		})
	}

	ok(c, "ok", gin.H{"certificates": out, "checked_at": now})
}
