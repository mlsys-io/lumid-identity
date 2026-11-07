package handler

// Model throughput (lum.id/code "Throughput") for the Anthropic pool.
//
//   POST /api/v1/internal/model-usage   {rows:[{source,model,minute,requests,...}]}  (claude-proxy)
//   GET  /api/v1/admin/model-usage?minutes=60&source=claude
//        -> {series, summary, minutes, live:{claude_streams}} — same shape as soc-keys/usage.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var modelUsageLastPrune time.Time

func InternalModelUsage(c *gin.Context) {
	var body struct {
		Rows []struct {
			Source    string `json:"source"`
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
	rows := make([]models.ModelUsageMinute, 0, len(body.Rows))
	for _, r := range body.Rows {
		if r.Source == "" || r.Model == "" || r.Minute <= 0 || len(r.Model) > 96 || len(r.Source) > 32 {
			continue
		}
		rows = append(rows, models.ModelUsageMinute{
			Source: r.Source, Model: r.Model, Minute: time.Unix(r.Minute/60*60, 0).UTC(),
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
	if err := common.DB.Clauses(clause.OnConflict{DoUpdates: clause.Set{
		add("requests"), add("errors"), add("streams"), add("in_tokens"), add("out_tokens"),
		add("gen_ms"), add("ttft_ms"), add("estimated"),
	}}).Create(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "store model usage: "+err.Error())
		return
	}
	if time.Since(modelUsageLastPrune) > time.Hour {
		modelUsageLastPrune = time.Now()
		common.DB.Where("minute < ?", time.Now().Add(-socUsageRetention)).Delete(&models.ModelUsageMinute{})
	}
	ok(c, "ok", gin.H{"stored": len(rows)})
}

func AdminModelUsage(c *gin.Context) {
	minutes, _ := strconv.Atoi(c.DefaultQuery("minutes", "60"))
	if minutes <= 0 || minutes > 7*24*60 {
		minutes = 60
	}
	source := c.DefaultQuery("source", "claude")
	now := time.Now().UTC()
	var series []socUsagePoint
	if err := common.DB.Model(&models.ModelUsageMinute{}).
		Select("minute, model, SUM(requests) requests, SUM(errors) errors, SUM(streams) streams, SUM(in_tokens) in_tokens, SUM(out_tokens) out_tokens, SUM(gen_ms) gen_ms, SUM(ttft_ms) ttft_ms").
		Where("source = ? AND minute >= ?", source, now.Add(-time.Duration(minutes)*time.Minute)).
		Group("minute, model").Order("minute").Scan(&series).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "model usage: "+err.Error())
		return
	}
	var live gin.H
	if source == "onprem" {
		if st := fetchOnpremStats(); st.Available {
			streams := map[string]int{}
			for _, b := range st.Backends {
				if !onpremSampled(b) {
					continue
				}
				streams[b.Label] += int(b.Inflight)
			}
			live = gin.H{"streams": streams, "observed_at": time.Now().UTC(), "source": "lumid-llm"}
		}
	} else if l := fetchSocRelayLive(); l != nil {
		live = gin.H{"streams": l.ClaudeStreams, "observed_at": l.ObservedAt, "source": l.Source}
	}
	ok(c, "ok", gin.H{"series": series, "summary": summarizeUsage(series, now), "minutes": minutes, "live": live})
}

// onpremSampled: real on-prem GPU backends only — the SoC relay is lumid-llm's
// tier 0 too, but it is not a GPU and has its own (keyed) throughput view.
func onpremSampled(b onpremBackendStats) bool {
	return !strings.Contains(b.URL, "claude-proxy-soc")
}

// StartOnpremThroughputSampler snapshots lumid-llm's per-backend stats once a
// minute into model_usage_minutes (source "onprem", model = backend label), so
// on-prem GPUs get the same per-minute series as the Claude pool and SoC.
// lumid-llm only exposes a rolling tok/s + current in-flight, so the row for the
// minute that just ended carries out_tokens = tok_s*60, requests = qps*60 and
// gen_ms = in-flight*60000 (=> "tok/s per stream" = tok_s / in-flight); no TTFT.
// Every identity replica runs it; the upsert REPLACES (a snapshot, not a sum),
// so two replicas writing the same minute cannot double-count.
func StartOnpremThroughputSampler() {
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			sampleOnprem(time.Now().UTC())
		}
	}()
}

func sampleOnprem(now time.Time) {
	st := fetchOnpremStats()
	if !st.Available || common.DB == nil {
		return
	}
	minute := now.Truncate(time.Minute).Add(-time.Minute)
	rows := []models.ModelUsageMinute{}
	for _, b := range st.Backends {
		if !onpremSampled(b) || b.Label == "" {
			continue
		}
		r := models.ModelUsageMinute{Source: "onprem", Model: b.Label, Minute: minute}
		if b.TokS != nil {
			r.OutTokens = int64(*b.TokS * 60)
		}
		if b.QPS != nil {
			r.Requests = int(*b.QPS*60 + 0.5)
		}
		inflight := int64(b.Inflight)
		if inflight == 0 && r.OutTokens > 0 {
			inflight = 1
		}
		r.GenMs = inflight * 60000
		if !b.Healthy {
			r.Errors = 1
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return
	}
	common.DB.Clauses(clause.OnConflict{UpdateAll: true}).Create(&rows)
}
