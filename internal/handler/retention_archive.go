package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"lumid_identity/internal/common"
)

// Cold-row retention for the append-only tables on the auth authority's DB.
//
// WHY THIS EXISTS. `lumid_identity` lives on a 2 Gi PVC shared with
// trading_community and lumid_cluster. It filled to 100% on 2026-09-15: the
// binlog write blocked, every COMMIT wedged in "waiting for handler commit",
// connections hit max_connections, and both identity replicas crashlooped on
// "Error 1040: Too many connections" — auth down estate-wide. That is the
// second fill (95% on 2026-08-17). A full volume here does not degrade
// gracefully, and the tables below only ever grow.
//
// Measured 2026-09-15, the three live growth drivers:
//
//	claude_session_turns  252 MB  12,781 rows/day
//	usage_events          166 MB  16,030 rows/day
//	me_app_runs            69 MB   2,779 rows/day
//
// ~14 MB/day combined, accelerating. Deleting alone is not enough — these rows
// are the only record of what the platform did — so the sweep ARCHIVES each
// batch to object storage as gzipped NDJSON before removing it.
//
// WHAT IS NOT SWEPT, AND WHY.
//   - `me_app_runs` is pinned by AdminAppInsights' insightsMaxDays = 365 and
//     has nothing older yet (oldest row 2026-07-08). Revisit when rows age past
//     a year, or if insightsMaxDays is ever lowered.
//
// `audit_log` IS swept, correcting the 2026-09-15 reading of it as "frozen,
// 2 rows/day". That count keyed on created_at, and 755,034 of its 756,638 rows
// (~130 MB) had created_at NULL — the raw INSERT in recordIntrospectAudit never
// set it (fixed in the same change). Those rows are /oauth/introspect hits from
// before introspect auditing was narrowed to legacy prefixes; no reader can
// select them, since every audit_log reader windows on created_at. nullTsIsCold
// archives them; dated rows keep the 365-day reader cap plus slack.
//
// The volume filled a THIRD time on 2026-09-18, three days after this sweep was
// written: it was never committed, so it never ran.
//   - `sessions` has its own reclaim loop (StartSessionReclaimLoop); its rows
//     die on expiry, not on age, so retention there is a different question.
//
// RETENTION WINDOWS COME FROM THE READERS, not from taste. For usage_events the
// widest bound in the codebase is me_audit.go's since_hours cap of 24*30 = 30
// days; quota.go reads only today plus the 5-hour/7-day pool anchors, and
// claude_balance.go trails 7 days. 35 days is that 30-day cap plus slack, so a
// surface at its maximum lookback still reads a fully populated table.
const (
	// A pass that deleted at least this many rows from a table rebuilds it.
	// InnoDB never returns freed pages to the filesystem on its own — `sessions`
	// sat at 1 MB of data inside 182 MB of file after its reclaim loop ran — so
	// without the rebuild a sweep bounds row count but not the volume.
	retentionOptimizeMinRows = 50000

	retentionSweepEvery = 6 * time.Hour
	// The first pass runs shortly after boot, not one full interval later.
	// Sleeping first meant any restart reset the countdown, and identity
	// ships several releases a day (11 in the four days to 2026-09-19), so a
	// sleep-first loop could go days without a single pass.
	reclaimFirstPassDelay = 10 * time.Minute
	retentionSweepBatch   = 5000
	retentionSweepMaxIter = 40 // bounds one pass at 200k rows per table
)

// archiveSpec describes one table the sweep may act on. tsColumn is the column
// retention is measured against; idColumn must be a monotonic autoincrement so
// a batch is addressable as a contiguous range.
type archiveSpec struct {
	table     string
	idColumn  string
	tsColumn  string
	retention time.Duration
	// envKey overrides retention in days at boot; "" means not tunable.
	envKey string
	// nullTsIsCold also archives rows whose tsColumn is NULL. Only for tables
	// where a NULL timestamp is a known writer bug and no reader can see the
	// row (see audit_log above) — otherwise NULL means "unknown", not "old".
	nullTsIsCold bool
}

// retentionSpecs is the full set the sweep knows how to handle. A table is only
// swept if its retention resolves > 0 — see resolveRetention.
//
// claude_session_turns defaults to 90 days (operator decision, 2026-09-19). Its
// blobs already live in S3 (BlobKey != ""), so the rows here are metadata — but
// deleting them makes the parent claude_sessions summary unopenable, since the
// transcript surface reconstructs a conversation by concatenating its turns. So
// /code can open sessions up to 90 days back; older turns are in the archive.
// It is the largest table (252 MB), so leaving it unbounded was not an option.
// Tune with RETENTION_TURNS_DAYS.
var retentionSpecs = []archiveSpec{
	{
		table:     "usage_events",
		idColumn:  "id",
		tsColumn:  "ts",
		retention: 35 * 24 * time.Hour,
		envKey:    "RETENTION_USAGE_EVENTS_DAYS",
	},
	{
		table:     "claude_session_turns",
		idColumn:  "id",
		tsColumn:  "ts",
		retention: 90 * 24 * time.Hour,
		envKey:    "RETENTION_TURNS_DAYS",
	},
	{
		table:        "audit_log",
		idColumn:     "id",
		tsColumn:     "created_at",
		retention:    400 * 24 * time.Hour, // insightsMaxDays (365) + slack
		envKey:       "RETENTION_AUDIT_LOG_DAYS",
		nullTsIsCold: true,
	},
}

// StartRetentionSweep archives and deletes cold rows on a timer.
//
// Disabled unless common.Blobs is configured. This is deliberate and load
// bearing: with no archive target the sweep would be a plain DELETE, and these
// rows are the only record of platform usage. No object store, no sweep — the
// volume filling is recoverable, silently destroying the usage record is not.
func StartRetentionSweep() {
	if common.Blobs == nil {
		log.Print("retention sweep: disabled (no object store configured — refusing to delete rows with nowhere to archive them)")
		return
	}
	active := activeSpecs()
	if len(active) == 0 {
		log.Print("retention sweep: no table has a retention window configured")
		return
	}
	names := make([]string, 0, len(active))
	for _, s := range active {
		names = append(names, fmt.Sprintf("%s>%dd", s.table, int(s.retention.Hours()/24)))
	}
	go func() {
		time.Sleep(reclaimFirstPassDelay)
		for {
			for _, spec := range active {
				n, bytesOut, err := sweepTable(spec)
				if errors.Is(err, errLockBusy) {
					log.Printf("retention sweep %s: skipped, another replica holds the lock", spec.table)
					continue
				}
				if err != nil {
					log.Printf("retention sweep %s failed: %v", spec.table, err)
					continue
				}
				if n > 0 {
					log.Printf("retention sweep %s: archived+deleted %d row(s), %d KB to object storage", spec.table, n, bytesOut/1024)
				}
			}
			time.Sleep(retentionSweepEvery)
		}
	}()
	log.Printf("retention sweep every %v, first pass in %v (%s)", retentionSweepEvery, reclaimFirstPassDelay, strings.Join(names, " "))
}

// activeSpecs resolves env overrides and returns only the tables to sweep.
func activeSpecs() []archiveSpec {
	out := []archiveSpec{}
	for _, s := range retentionSpecs {
		if s.envKey != "" {
			if v := os.Getenv(s.envKey); v != "" {
				days, err := strconv.Atoi(v)
				if err != nil || days < 1 {
					log.Printf("retention sweep: ignoring %s=%q (want a positive integer number of days)", s.envKey, v)
				} else {
					s.retention = time.Duration(days) * 24 * time.Hour
				}
			}
		}
		if s.retention > 0 {
			out = append(out, s)
		}
	}
	return out
}

// sweepTable archives then deletes one table's cold rows, oldest first.
//
// Serialised across replicas by a MySQL named lock (withNamedLock): identity
// runs replicas:2 and two concurrent sweeps would upload the same rows twice
// and contend on the same deletes. Returns errLockBusy if another holds it.
func sweepTable(spec archiveSpec) (n int64, bytesOut int, err error) {
	err = withNamedLock(common.DB, "retention_sweep", 2*time.Second, func() error {
		var e error
		n, bytesOut, e = sweepTableLocked(spec)
		return e
	})
	return n, bytesOut, err
}

func sweepTableLocked(spec archiveSpec) (int64, int, error) {
	cutoff := time.Now().UTC().Add(-spec.retention)

	// Cheap early-out. None of these tables index the ts column on its own, so
	// the batch SELECT walks the primary key; when nothing is cold that walk is
	// a full-table scan every 6h, flushing the buffer pool of a 2Gi-limit DB.
	if cold, err := hasColdHead(spec, cutoff); err != nil {
		return 0, 0, fmt.Errorf("head check: %w", err)
	} else if !cold {
		return 0, 0, nil
	}

	var total int64
	var totalBytes int

	for i := 0; i < retentionSweepMaxIter; i++ {
		// Oldest-first by id so a batch is a contiguous id range, and so an
		// interrupted sweep resumes where it stopped instead of restarting.
		var rows []map[string]interface{}
		err := common.DB.
			Table(spec.table).
			Where(coldPredicate(spec), cutoff).
			Order(spec.idColumn + " ASC").
			Limit(retentionSweepBatch).
			Find(&rows).Error
		if err != nil {
			return total, totalBytes, fmt.Errorf("select: %w", err)
		}
		if len(rows) == 0 {
			break
		}

		minID, maxID, err := idRange(rows, spec.idColumn)
		if err != nil {
			return total, totalBytes, err
		}

		payload, err := encodeNDJSONGz(rows)
		if err != nil {
			return total, totalBytes, fmt.Errorf("encode: %w", err)
		}

		// ARCHIVE BEFORE DELETE, and only delete if the upload returned no
		// error. A failed PUT leaves the rows in place and the next pass
		// retries the same range — the sweep loses a cycle, never a row.
		key := fmt.Sprintf("%s/%s-%d-%d.ndjson.gz",
			spec.table, time.Now().UTC().Format("20060102T150405Z"), minID, maxID)
		if err := common.Blobs.PutArchive(key, payload); err != nil {
			return total, totalBytes, fmt.Errorf("archive %s: %w", key, err)
		}
		totalBytes += len(payload)

		// Delete exactly the range just archived. Bounding by id AND repeating
		// the ts predicate makes this precise: every row in [minID,maxID] older
		// than the cutoff is in the batch, because the batch was the first N
		// such rows by id. Autoincrement means later inserts land above maxID,
		// so nothing new can fall inside the range between select and delete.
		res := common.DB.Exec(
			fmt.Sprintf("DELETE FROM %s WHERE %s >= ? AND %s <= ? AND %s",
				spec.table, spec.idColumn, spec.idColumn, coldPredicate(spec)),
			minID, maxID, cutoff)
		if res.Error != nil {
			// The archive object is already written. Leaving it is correct:
			// re-running produces a new object for the same range, and a
			// duplicate archive is recoverable where a missing one is not.
			return total, totalBytes, fmt.Errorf("delete %s [%d,%d] (archived to %s%s): %w",
				spec.table, minID, maxID, common.ArchivePrefix, key, res.Error)
		}
		total += res.RowsAffected

		if len(rows) < retentionSweepBatch {
			break
		}
	}

	// Still under the named lock, so only one replica rebuilds. OPTIMIZE on
	// InnoDB is an online rebuild (DML continues) that needs free space about
	// the table's size while it runs. A failure only costs the reclaim.
	if total >= retentionOptimizeMinRows {
		if err := optimizeTable(spec.table); err != nil {
			log.Printf("retention sweep %s: OPTIMIZE failed (rows are archived and deleted; only the disk reclaim was lost): %v", spec.table, err)
		}
	}
	return total, totalBytes, nil
}

// hasColdHead reports whether any of the lowest-id retentionSweepBatch rows is
// past retention — a bounded PK read, unlike a bare "any cold row?" probe.
//
// It checks a WINDOW, not just the lowest row. Ids are autoincrement, so the
// head of the table is its oldest part, but it is not uniformly cold: a sweep
// deletes only the cold rows and keeps any newer row interleaved among them.
// On 2026-09-19 the first audit_log pass removed 200k NULL-created_at rows and
// left the dated ones; the lowest id became a 2026-05-11 row inside the
// 400-day window, and a lowest-row-only check skipped the table with 555k cold
// rows still behind it. A window of one batch tolerates up to a batch of kept
// rows ahead of the cold ones.
func hasColdHead(spec archiveSpec, cutoff time.Time) (bool, error) {
	var n int64
	err := common.DB.Raw(fmt.Sprintf(
		"SELECT COUNT(*) FROM (SELECT %s FROM %s ORDER BY %s ASC LIMIT %d) h WHERE %s",
		spec.tsColumn, spec.table, spec.idColumn, retentionSweepBatch, coldPredicate(spec)), cutoff).
		Scan(&n).Error
	return n > 0, err
}

// coldPredicate is the WHERE fragment selecting rows past retention, with one
// placeholder for the cutoff. SELECT and DELETE must share it exactly: the
// delete's precision argument rests on both matching the same rows.
func coldPredicate(spec archiveSpec) string {
	if spec.nullTsIsCold {
		return fmt.Sprintf("(%s < ? OR %s IS NULL)", spec.tsColumn, spec.tsColumn)
	}
	return fmt.Sprintf("%s < ?", spec.tsColumn)
}

// optimizeTable runs OPTIMIZE TABLE. It returns a result set whose Msg_type
// column reports failures, so the rows are read rather than trusting Exec.
func optimizeTable(table string) error {
	rows, err := common.DB.Raw("OPTIMIZE TABLE " + table).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tbl, op, msgType, msgText string
		if err := rows.Scan(&tbl, &op, &msgType, &msgText); err != nil {
			return err
		}
		if strings.EqualFold(msgType, "error") {
			return fmt.Errorf("%s: %s", tbl, msgText)
		}
	}
	return rows.Err()
}

// idRange returns the smallest and largest id in a batch. The driver hands back
// autoincrement columns as int64 or []byte depending on the column type, so
// both are accepted rather than assuming one.
func idRange(rows []map[string]interface{}, idColumn string) (int64, int64, error) {
	var min, max int64
	for i, r := range rows {
		raw, ok := r[idColumn]
		if !ok {
			return 0, 0, fmt.Errorf("row %d has no %q column", i, idColumn)
		}
		v, err := toInt64(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("row %d: %q: %w", i, idColumn, err)
		}
		if i == 0 || v < min {
			min = v
		}
		if i == 0 || v > max {
			max = v
		}
	}
	return min, max, nil
}

func toInt64(raw interface{}) (int64, error) {
	switch v := raw.(type) {
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case int:
		return int64(v), nil
	case []byte:
		return strconv.ParseInt(string(v), 10, 64)
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("unsupported id type %T", raw)
	}
}

// encodeNDJSONGz renders a batch as gzipped newline-delimited JSON — one row
// per line, so a restore can stream the object instead of holding the whole
// batch in memory, and a truncated object still yields every complete line
// before the cut.
func encodeNDJSONGz(rows []map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range rows {
		// []byte columns marshal as base64 and come back unreadable. Render
		// them as text so an archived row stays greppable.
		for k, v := range r {
			if b, ok := v.([]byte); ok {
				r[k] = string(b)
			}
		}
		if err := enc.Encode(r); err != nil {
			zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
