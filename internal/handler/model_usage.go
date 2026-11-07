package handler

// Model throughput (lum.id/code "Throughput") for the Anthropic pool.
//
//   POST /api/v1/internal/model-usage   {rows:[{source,model,minute,requests,...}]}  (claude-proxy)
//   GET  /api/v1/admin/model-usage?minutes=60&source=claude
//        -> {series, summary, minutes, live:{claude_streams}} — same shape as soc-keys/usage.

import (
	"net/http"
	"strconv"
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
	if l := fetchSocRelayLive(); l != nil {
		live = gin.H{"streams": l.ClaudeStreams, "observed_at": l.ObservedAt, "source": l.Source}
	}
	ok(c, "ok", gin.H{"series": series, "summary": summarizeUsage(series, now), "minutes": minutes, "live": live})
}
