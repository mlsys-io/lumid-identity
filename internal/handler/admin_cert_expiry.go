package handler

import (
	"crypto/tls"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// GET /admin/cert-expiry — super-admin dashboard tile.
//
// Reads the expiry off the certificates the edge is ACTUALLY SERVING, by
// completing a TLS handshake to each host and taking NotAfter from the leaf.
//
// It used to proxy Prometheus (`probe_ssl_earliest_cert_expiry{job="blackbox-tls"}`),
// with PROMETHEUS_URL defaulting to host.docker.internal:9090 — a pre-UKS
// docker-compose address. kube-prometheus-stack was torn down 2026-07-04 and
// nothing reinstalls it, so every call has returned
// `502 {"message":"prometheus unreachable"}` since then, and the CERT EXPIRY
// tile on /studio/super-admin has rendered a blank em-dash for weeks. A blank
// where a countdown belongs reads as "nothing expiring soon", which is the
// worst way for this particular tile to fail: LB cert bundles are wiped by the
// UpCloud CCM on every reconcile and restored by the lb-cert-reconcile CronJob,
// so "how many days left" is a number someone actually needs to see.
//
// Dialling directly is also a straighter answer than the old one. The blackbox
// probe measured what Prometheus could reach; this measures what a browser
// gets, which is the thing the tile claims to report. No new dependency, and
// it works whether or not a monitoring stack exists.
//
// Hosts come from CERT_EXPIRY_HOSTS (comma-separated) so adding one is a
// manifest edit. Failures are reported per-host rather than failing the whole
// tile: one unreachable name must not blank the others.
func AdminCertExpiry(c *gin.Context) {
	type certRow struct {
		Domain    string    `json:"domain"`
		ExpiresAt time.Time `json:"expires_at"`
		DaysLeft  int       `json:"days_left"`
	}

	hosts := certExpiryHosts()
	now := time.Now().UTC()

	var mu sync.Mutex
	out := make([]certRow, 0, len(hosts))
	probeErrs := make([]string, 0)

	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			d := &net.Dialer{Timeout: 6 * time.Second}
			conn, err := tls.DialWithDialer(d, "tcp", host+":443", &tls.Config{
				ServerName: host,
				// MinVersion satisfies gosec; the edge is TLS 1.2+ anyway.
				MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				mu.Lock()
				probeErrs = append(probeErrs, host+": "+err.Error())
				mu.Unlock()
				return
			}
			defer conn.Close()
			chain := conn.ConnectionState().PeerCertificates
			if len(chain) == 0 {
				mu.Lock()
				probeErrs = append(probeErrs, host+": no peer certificate")
				mu.Unlock()
				return
			}
			exp := chain[0].NotAfter.UTC()
			mu.Lock()
			out = append(out, certRow{
				Domain:    host,
				ExpiresAt: exp,
				DaysLeft:  int(exp.Sub(now).Hours() / 24),
			})
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	// Soonest-to-expire first: the tile shows a handful, and the one about to
	// lapse is the one worth seeing.
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	sort.Strings(probeErrs)

	ok(c, "ok", gin.H{
		"certificates": out,
		"checked_at":   now,
		// Present so a partial result is legible as partial rather than as
		// "these are all the certs there are".
		"errors": probeErrs,
	})
}

// certExpiryHosts returns the TLS names to probe. Override with
// CERT_EXPIRY_HOSTS="a.example,b.example".
func certExpiryHosts() []string {
	raw := strings.TrimSpace(os.Getenv("CERT_EXPIRY_HOSTS"))
	if raw == "" {
		// The public names the edge LB terminates. sql.lum.id is deliberately
		// absent: it is a Postgres-wire frontend on 5432, not an HTTPS vhost,
		// so a :443 handshake there would report a failure that means nothing.
		raw = "lum.id,xp.io,lumid.market,lumid.trade"
	}
	seen := map[string]bool{}
	hosts := make([]string, 0, 4)
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(strings.ToLower(s)); s != "" && !seen[s] {
			seen[s] = true
			hosts = append(hosts, s)
		}
	}
	return hosts
}
