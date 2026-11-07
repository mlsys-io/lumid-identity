package handler

// SoC relay usage (TKPS) — ingest from claude-proxy + read for lum.id/code.
//
//   POST /api/v1/internal/soc-keys/usage  {rows:[{key_id,model,minute,requests,...}]}
//   GET  /api/v1/admin/soc-keys/usage?minutes=60
//        -> per-minute series per model + last-5-min summary (aggregate output
//           tok/s, per-stream decode tok/s, avg TTFT) + per-key totals today (SGT).

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const socUsageRetention = 30 * 24 * time.Hour

var socUsageLastPrune time.Time

func InternalSocKeyUsage(c *gin.Context) {
	var body struct {
		Rows []struct {
			KeyID     uint   `json:"key_id"`
			Model     string `json:"model"`
			Minute    int64  `json:"minute"`
			Requests  int    `json:"requests"`
			Errors    int    `json:"errors"`
			Streams   int    `json:"streams"`
			InTokens  int64  `json:"in_tokens"`
			OutTokens int64  `json:"out_tokens"`
			GenMs     int64  `json:"gen_ms"`
			TTFTMs    int64  `json:"ttft_ms"`
			Estimated int    `json:"estimated"`
		} `json:"rows"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	rows := make([]models.SocKeyUsage, 0, len(body.Rows))
	for _, r := range body.Rows {
		if r.Model == "" || r.Minute <= 0 || len(r.Model) > 64 {
			continue
		}
		rows = append(rows, models.SocKeyUsage{
			KeyID: r.KeyID, Model: r.Model, Minute: time.Unix(r.Minute/60*60, 0).UTC(),
			Requests: r.Requests, Errors: r.Errors, Streams: r.Streams,
			InTokens: r.InTokens, OutTokens: r.OutTokens, GenMs: r.GenMs, TTFTMs: r.TTFTMs, Estimated: r.Estimated,
		})
	}
	if len(rows) == 0 {
		ok(c, "ok", gin.H{"stored": 0})
		return
	}
	add := func(col string) clause.Assignment {
		return clause.Assignment{Column: clause.Column{Name: col}, Value: gorm.Expr(col + " + VALUES(" + col + ")")}
	}
	err := common.DB.Clauses(clause.OnConflict{DoUpdates: clause.Set{
		add("requests"), add("errors"), add("streams"), add("in_tokens"), add("out_tokens"),
		add("gen_ms"), add("ttft_ms"), add("estimated"),
	}}).Create(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "store usage: "+err.Error())
		return
	}
	if time.Since(socUsageLastPrune) > time.Hour {
		socUsageLastPrune = time.Now()
		common.DB.Where("minute < ?", time.Now().Add(-socUsageRetention)).Delete(&models.SocKeyUsage{})
	}
	ok(c, "ok", gin.H{"stored": len(rows)})
}

type socUsagePoint struct {
	Minute    time.Time `json:"minute"`
	Model     string    `json:"model"`
	Requests  int       `json:"requests"`
	Errors    int       `json:"errors"`
	Streams   int       `json:"streams"`
	InTokens  int64     `json:"in_tokens"`
	OutTokens int64     `json:"out_tokens"`
	GenMs     int64     `json:"gen_ms"`
	TTFTMs    int64     `json:"ttft_ms"`
}

type socUsageSummary struct {
	Model        string  `json:"model"`
	Requests     int     `json:"requests"`
	Errors       int     `json:"errors"`
	InTokens     int64   `json:"in_tokens"`
	OutTokens    int64   `json:"out_tokens"`
	AggOutTPS    float64 `json:"agg_out_tps"` // output tokens / window seconds
	StreamTPS    float64 `json:"stream_tps"`  // output tokens / generation seconds (per-stream decode)
	AvgTTFTMs    float64 `json:"avg_ttft_ms"`
	WindowMinute int     `json:"window_minutes"`
}

type socKeyToday struct {
	KeyID     uint  `json:"key_id"`
	Requests  int   `json:"requests"`
	Errors    int   `json:"errors"`
	InTokens  int64 `json:"in_tokens"`
	OutTokens int64 `json:"out_tokens"`
}

// sgtDayStart is the start of the current day in Asia/Singapore (UTC+8), the
// SoC gateway's home timezone and our best guess for its daily-limit reset.
func sgtDayStart(now time.Time) time.Time {
	sgt := time.FixedZone("SGT", 8*3600)
	t := now.In(sgt)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, sgt)
}

func AdminSocKeysUsage(c *gin.Context) {
	minutes, _ := strconv.Atoi(c.DefaultQuery("minutes", "60"))
	if minutes <= 0 || minutes > 7*24*60 {
		minutes = 60
	}
	now := time.Now().UTC()
	since := now.Add(-time.Duration(minutes) * time.Minute)

	var series []socUsagePoint
	if err := common.DB.Model(&models.SocKeyUsage{}).
		Select("minute, model, SUM(requests) requests, SUM(errors) errors, SUM(streams) streams, SUM(in_tokens) in_tokens, SUM(out_tokens) out_tokens, SUM(gen_ms) gen_ms, SUM(ttft_ms) ttft_ms").
		Where("minute >= ?", since).Group("minute, model").Order("minute").Scan(&series).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "usage series: "+err.Error())
		return
	}

	summary := summarizeUsage(series, now)

	var today []socKeyToday
	common.DB.Model(&models.SocKeyUsage{}).
		Select("key_id, SUM(requests) requests, SUM(errors) errors, SUM(in_tokens) in_tokens, SUM(out_tokens) out_tokens").
		Where("minute >= ?", sgtDayStart(now).UTC()).Group("key_id").Scan(&today)

	ok(c, "ok", gin.H{"series": series, "summary": summary, "keys_today": today, "minutes": minutes, "live": fetchSocRelayLive()})
}

// socRelayLive is claude-proxy's SoC relay /status: what is running RIGHT NOW,
// read from the per-key Redis locks (one in-flight request per key), so it is
// cluster-wide whichever proxy replica answers.
type socRelayLive struct {
	Streams    map[string]int `json:"streams"`
	BusyKeys   []uint         `json:"busy_keys"`
	Waiting    int64          `json:"waiting"`
	Source     string         `json:"source"`
	ObservedAt time.Time      `json:"observed_at"`
	// Anthropic-pool streams in flight per model (claude-proxy modelusage.go).
	ClaudeStreams map[string]int `json:"claude_streams"`
}

var socRelayClient = &http.Client{Timeout: 2 * time.Second}

// fetchSocRelayLive is best-effort: nil when the relay is unreachable, so the
// usage view never fails because of it.
func fetchSocRelayLive() *socRelayLive {
	url := os.Getenv("SOC_RELAY_STATUS_URL")
	if url == "" {
		url = "http://claude-proxy-soc.lumid.svc.cluster.local:8081/status"
	}
	resp, err := socRelayClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out socRelayLive
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	return &out
}

// summarizeUsage: per-model tiles over the last 5 complete minutes (the current
// minute is still being filled by the proxies' 60 s flush, so it is excluded).
func summarizeUsage(series []socUsagePoint, now time.Time) []socUsageSummary {
	// Summary over the last 5 complete-ish minutes (the current minute is
	// still being filled by the proxies' 60s flush, so it is excluded).
	const win = 5
	winEnd := now.Truncate(time.Minute)
	winStart := winEnd.Add(-win * time.Minute)
	sum := map[string]*socUsageSummary{}
	var genMs, ttftMs, streams = map[string]int64{}, map[string]int64{}, map[string]int{}
	for _, p := range series {
		if p.Minute.Before(winStart) || !p.Minute.Before(winEnd) {
			continue
		}
		s := sum[p.Model]
		if s == nil {
			s = &socUsageSummary{Model: p.Model, WindowMinute: win}
			sum[p.Model] = s
		}
		s.Requests += p.Requests
		s.Errors += p.Errors
		s.InTokens += p.InTokens
		s.OutTokens += p.OutTokens
		genMs[p.Model] += p.GenMs
		ttftMs[p.Model] += p.TTFTMs
		streams[p.Model] += p.Streams
	}
	summary := make([]socUsageSummary, 0, len(sum))
	for m, s := range sum {
		s.AggOutTPS = float64(s.OutTokens) / float64(win*60)
		if genMs[m] > 0 {
			s.StreamTPS = float64(s.OutTokens) / (float64(genMs[m]) / 1000)
		}
		if streams[m] > 0 {
			s.AvgTTFTMs = float64(ttftMs[m]) / float64(streams[m])
		}
		summary = append(summary, *s)
	}

	return summary
}
