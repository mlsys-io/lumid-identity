package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// GET /admin/qa-summary — super-admin dashboard tile.
//
// Crosses into the QuantArena schema (`trading_community.*`) using the
// same MySQL connection. Identity already authenticates as root, so a
// cross-schema read is free. Conceptually QA-owned, mechanically
// cheaper here than spinning up an HTTP call to QA backend just for
// these counts.

type qaSummaryResp struct {
	Strategies struct {
		Total  int64 `json:"total"`
		Active int64 `json:"active"` // versions with status='running' or similar
	} `json:"strategies"`
	Competitions struct {
		Total    int64 `json:"total"`
		Ongoing  int64 `json:"ongoing"`
		Upcoming int64 `json:"upcoming"`
	} `json:"competitions"`
	Trades24h struct {
		Count int64 `json:"count"`
	} `json:"trades_24h"`
	Generated time.Time `json:"generated_at"`
}

func AdminQASummary(c *gin.Context) {
	var resp qaSummaryResp
	resp.Generated = time.Now().UTC()

	// Strategies — total rows, plus distinct strategies enrolled in any
	// active competition (proxy for "active strategies" since
	// tbl_strategy_version has no status column).
	common.DB.Raw(
		`SELECT COUNT(*) FROM trading_community.tbl_strategy`,
	).Scan(&resp.Strategies.Total)
	common.DB.Raw(
		`SELECT COUNT(DISTINCT p.simulation_strategy_id)
		 FROM trading_community.tbl_competition_participant p
		 JOIN trading_community.tbl_competition c ON c.id = p.competition_id
		 WHERE c.start_time <= UNIX_TIMESTAMP() * 1000
		   AND (c.end_time IS NULL OR c.end_time > UNIX_TIMESTAMP() * 1000)`,
	).Scan(&resp.Strategies.Active)

	// Competitions — start_time / end_time are bigint epoch milliseconds
	// (per `DESCRIBE tbl_competition`), not MySQL timestamps. Compare
	// against UNIX_TIMESTAMP() * 1000 instead of NOW().
	common.DB.Raw(
		`SELECT COUNT(*) FROM trading_community.tbl_competition`,
	).Scan(&resp.Competitions.Total)
	common.DB.Raw(
		`SELECT COUNT(*) FROM trading_community.tbl_competition
		 WHERE start_time <= UNIX_TIMESTAMP() * 1000
		   AND (end_time IS NULL OR end_time > UNIX_TIMESTAMP() * 1000)`,
	).Scan(&resp.Competitions.Ongoing)
	common.DB.Raw(
		`SELECT COUNT(*) FROM trading_community.tbl_competition
		 WHERE start_time > UNIX_TIMESTAMP() * 1000`,
	).Scan(&resp.Competitions.Upcoming)

	// 24h trade volume — `create_time` (bigint epoch ms), not created_at.
	common.DB.Raw(
		`SELECT COUNT(*) FROM trading_community.tbl_competition_trade
		 WHERE create_time >= (UNIX_TIMESTAMP() - 86400) * 1000`,
	).Scan(&resp.Trades24h.Count)

	ok(c, "ok", resp)
}
