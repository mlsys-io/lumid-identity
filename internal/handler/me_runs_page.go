package handler

// /me/runs pagination.
//
// The offset cursor this replaces had two faults:
//
//   - It paged over ONE scan of the sources, and the run store's scan is
//     capped at runStoreScanCap (500) newest rows. So nothing past the 500th
//     run in the window was reachable by any cursor — the feed simply ended.
//   - An offset shifts whenever a new run lands at the head, so walking pages
//     while runs were being recorded produced duplicates. An offset past the
//     end also sliced out of range (startIdx > endIdx), which panicked.
//
// The keyset cursor names the last row returned — (started_at, run_id) — and
// the next page re-scans the sources from there. Order is total:
// started_at DESC, then run_id DESC, so equal timestamps cannot reorder
// between pages.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runCursorPrefix marks a keyset token. Legacy tokens are base64 of a bare
// integer, and "." is not a base64 character, so the two cannot collide.
const runCursorPrefix = "r1."

// runCursorMaxID sorts after every real run_id ("scheduled:…", "visual:…"),
// so a cursor carrying it admits every row AT its timestamp.
const runCursorMaxID = "\x7f"

type runCursor struct {
	T  float64 `json:"t"`
	ID string  `json:"id"`
}

func encodeRunCursor(cur runCursor) string {
	b, _ := json.Marshal(cur)
	return runCursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeRunCursor(tok string) (*runCursor, bool) {
	if !strings.HasPrefix(tok, runCursorPrefix) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, runCursorPrefix))
	if err != nil {
		return nil, false
	}
	var cur runCursor
	if json.Unmarshal(b, &cur) != nil || cur.T <= 0 {
		return nil, false
	}
	return &cur, true
}

// runsPage is the parsed pagination request: either a legacy offset
// (offset >= 0) or a keyset position (keyset, nil for the first page).
type runsPage struct {
	offset int
	keyset *runCursor
}

// parseRunsPageParams reads `cursor` and `before`.
//
//   - cursor: an opaque token from next_cursor. A keyset token, or a legacy
//     integer offset (still honoured). Anything undecodable is ignored, as it
//     always was — the first page is returned.
//   - before: a keyset token, OR a bare started_at — unix seconds ("1764000000",
//     fractions allowed) or RFC3339 — meaning "strictly older than this". A
//     value that is none of those is a 400: the param is new, nobody depends on
//     it being lenient, and a silently-ignored cursor re-serves page one.
func parseRunsPageParams(cursor, before string) (runsPage, error) {
	cursor, before = strings.TrimSpace(cursor), strings.TrimSpace(before)
	if cursor != "" && before != "" {
		return runsPage{}, errors.New("pass either cursor or before, not both")
	}
	if before != "" {
		if cur, ok := decodeRunCursor(before); ok {
			return runsPage{offset: -1, keyset: cur}, nil
		}
		if v, err := strconv.ParseFloat(before, 64); err == nil && v > 0 {
			return runsPage{offset: -1, keyset: &runCursor{T: v}}, nil
		}
		if t, err := time.Parse(time.RFC3339Nano, before); err == nil {
			return runsPage{offset: -1, keyset: &runCursor{T: float64(t.UnixNano()) / 1e9}}, nil
		}
		return runsPage{}, errors.New("invalid before: want a next_cursor token, unix seconds, or RFC3339")
	}
	if cursor == "" {
		return runsPage{offset: -1}, nil
	}
	if cur, ok := decodeRunCursor(cursor); ok {
		return runsPage{offset: -1, keyset: cur}, nil
	}
	if b, err := base64.URLEncoding.DecodeString(cursor); err == nil {
		if v, err := strconv.Atoi(string(b)); err == nil && v >= 0 {
			return runsPage{offset: v}, nil
		}
	}
	return runsPage{offset: -1}, nil
}

func filterRuns(rows []RunRow, stateFilter, workflowFilter string) []RunRow {
	out := make([]RunRow, 0, len(rows))
	for _, r := range rows {
		if stateFilter != "" && !stateMatches(r.State, stateFilter) {
			continue
		}
		if workflowFilter != "" && r.WorkflowSlug != workflowFilter {
			continue
		}
		out = append(out, r)
	}
	return out
}

// runOlder reports whether a sorts strictly AFTER b in feed order (i.e. is
// older): started_at DESC, run_id DESC.
func runOlder(a RunRow, b runCursor) bool {
	if a.StartedAt != b.T {
		return a.StartedAt < b.T
	}
	return a.RunID < b.ID
}

func sortRunsNewestFirst(rows []RunRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].StartedAt != rows[j].StartedAt {
			return rows[i].StartedAt > rows[j].StartedAt
		}
		return rows[i].RunID > rows[j].RunID
	})
}

func cursorOf(r RunRow) runCursor { return runCursor{T: r.StartedAt, ID: r.RunID} }

// pageByKeyset returns the page after `cur` (nil = first page) from rows
// already filtered and sorted newest first. storeCapped/storeOldest describe
// the run-store scan the rows came from (runRowsFromDBScan).
//
// When the store scan was capped, rows older than its oldest row are not
// trustworthy as a PAGE: the store holds more rows down there that this scan
// did not read, and serving a journal or n8n row from below that line would
// let the next cursor skip them. So the page is drawn only from rows strictly
// newer than the store's horizon, and the next request re-scans from the last
// row served. Rows AT the horizon are deferred too — the cap may have cut
// through them. The one exception is a scan whose every row shares a single
// second (more than 500 runs in one second for one user): there is nothing
// strictly newer, so the page is served from the horizon itself.
func pageByKeyset(rows []RunRow, cur *runCursor, limit int, storeCapped bool, storeOldest float64) ([]RunRow, int, string) {
	cands := rows
	if cur != nil {
		cands = make([]RunRow, 0, len(rows))
		for _, r := range rows {
			if runOlder(r, *cur) {
				cands = append(cands, r)
			}
		}
	}
	total := len(cands)

	window := cands
	if storeCapped {
		n := 0
		for n < len(cands) && cands[n].StartedAt > storeOldest {
			n++
		}
		if n > 0 {
			window = cands[:n]
		}
	}
	page := window
	if len(page) > limit {
		page = page[:limit]
	}
	more := len(window) > len(page) || len(cands) > len(window) || storeCapped
	if !more {
		return page, total, ""
	}
	var next runCursor
	if len(page) > 0 {
		next = cursorOf(page[len(page)-1])
	} else {
		// Filters emptied this slice of a capped scan. Continue from the
		// horizon, admitting every row at it.
		next = runCursor{T: storeOldest, ID: runCursorMaxID}
	}
	// Never hand back a cursor that does not advance: that is a client loop.
	if cur != nil && !(next.T < cur.T || (next.T == cur.T && next.ID < cur.ID)) {
		return page, total, ""
	}
	if next.T <= 0 {
		return page, total, ""
	}
	return page, total, encodeRunCursor(next)
}

// pageByOffset serves a LEGACY integer-offset cursor over one scan, as before,
// but clamps an out-of-range offset (it used to panic) and hands back a keyset
// token so the client's next request leaves offset mode. A capped store scan
// trims rows to its horizon first, for the reason pageByKeyset gives.
func pageByOffset(rows []RunRow, offset, limit int, storeCapped bool, storeOldest float64) ([]RunRow, int, string) {
	capped := false
	if storeCapped {
		n := 0
		for n < len(rows) && rows[n].StartedAt > storeOldest {
			n++
		}
		if n > 0 && n < len(rows) {
			rows, capped = rows[:n], true
		}
	}
	if offset > len(rows) {
		offset = len(rows)
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	page := rows[offset:end]
	if (end < len(rows) || capped) && len(page) > 0 {
		return page, len(rows), encodeRunCursor(cursorOf(page[len(page)-1]))
	}
	return page, len(rows), ""
}

// keysetScanUntil narrows the sources' upper bound to the cursor. Ceil, not
// floor: the run store keys whole seconds, and a journal row at 100.3 must
// survive a cursor at 100.7. The exact cut is made by pageByKeyset on
// (started_at, run_id).
func keysetScanUntil(cur *runCursor, until time.Time) time.Time {
	if cur == nil {
		return until
	}
	if cu := time.Unix(int64(math.Ceil(cur.T)), 0).UTC(); cu.Before(until) {
		return cu
	}
	return until
}
