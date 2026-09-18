package handler

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
)

// The sweep deletes by id RANGE, so a wrong min/max deletes rows it never
// archived. The MySQL driver hands autoincrement columns back as int64 or as
// []byte depending on column type and driver settings, and an unhandled type
// previously meant the range silently came back {0,0} — which as a DELETE bound
// matches nothing, or worse, matches from id 0 upward.
func TestIDRangeAcrossDriverTypes(t *testing.T) {
	cases := []struct {
		name string
		rows []map[string]interface{}
	}{
		{"int64", []map[string]interface{}{{"id": int64(7)}, {"id": int64(3)}, {"id": int64(9)}}},
		{"bytes", []map[string]interface{}{{"id": []byte("7")}, {"id": []byte("3")}, {"id": []byte("9")}}},
		{"uint64", []map[string]interface{}{{"id": uint64(7)}, {"id": uint64(3)}, {"id": uint64(9)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			min, max, err := idRange(tc.rows, "id")
			if err != nil {
				t.Fatalf("idRange: %v", err)
			}
			if min != 3 || max != 9 {
				t.Errorf("got [%d,%d], want [3,9]", min, max)
			}
		})
	}
}

// A missing id column must be a hard error, never a usable {0,0} range: the
// caller turns this straight into DELETE bounds.
func TestIDRangeRejectsMissingColumn(t *testing.T) {
	if _, _, err := idRange([]map[string]interface{}{{"ts": 1}}, "id"); err == nil {
		t.Fatal("idRange accepted a batch with no id column — a {0,0} range would " +
			"become a DELETE bound covering rows that were never archived")
	}
	if _, _, err := idRange([]map[string]interface{}{{"id": struct{}{}}}, "id"); err == nil {
		t.Fatal("idRange accepted an unparseable id type")
	}
}

// The archive is the only surviving copy once rows are deleted, so it must be
// faithful: one line per row, every row decodable, and []byte columns readable
// rather than base64.
func TestEncodeNDJSONGzRoundTrips(t *testing.T) {
	rows := []map[string]interface{}{
		{"id": int64(1), "kind": "chat", "meta": []byte(`{"a":1}`)},
		{"id": int64(2), "kind": "claude_proxy", "meta": []byte("")},
	}
	blob, err := encodeNDJSONGz(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	var got []map[string]interface{}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		var m map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		got = append(got, m)
	}
	if len(got) != len(rows) {
		t.Fatalf("got %d archived line(s), want %d", len(got), len(rows))
	}
	// Rendered as text, not base64 — an archived row has to stay greppable.
	if got[0]["meta"] != `{"a":1}` {
		t.Errorf("meta = %#v, want the raw JSON text", got[0]["meta"])
	}
}

// The default windows are operator decisions (2026-09-19): turns 90 days,
// usage_events 35, audit_log 400. A spec that silently drops out of the active
// set is how this DB filled three times, so assert every one is on.
func TestDefaultRetentionWindows(t *testing.T) {
	want := map[string]float64{"usage_events": 35, "claude_session_turns": 90, "audit_log": 400}
	got := map[string]float64{}
	for _, s := range activeSpecs() {
		got[s.table] = s.retention.Hours() / 24
	}
	for table, days := range want {
		if got[table] != days {
			t.Errorf("%s retention = %v days, want %v", table, got[table], days)
		}
	}

	// The override must actually take effect, otherwise the knob is decorative.
	t.Setenv("RETENTION_TURNS_DAYS", "120")
	for _, s := range activeSpecs() {
		if s.table == "claude_session_turns" && s.retention.Hours()/24 != 120 {
			t.Errorf("RETENTION_TURNS_DAYS=120 yielded %v days", s.retention.Hours()/24)
		}
	}
}

// NULL-timestamp rows are archived ONLY where that was chosen (audit_log). On
// any other table a NULL ts must not match: there it means "unknown", and the
// sweep would archive-and-delete a live row.
func TestColdPredicateNullHandling(t *testing.T) {
	for _, s := range retentionSpecs {
		p := coldPredicate(s)
		hasNull := strings.Contains(p, "IS NULL")
		if hasNull != s.nullTsIsCold {
			t.Errorf("%s: predicate %q, nullTsIsCold=%v", s.table, p, s.nullTsIsCold)
		}
		if strings.Count(p, "?") != 1 {
			t.Errorf("%s: predicate %q must take exactly one cutoff placeholder", s.table, p)
		}
		if s.nullTsIsCold && s.table != "audit_log" {
			t.Errorf("%s archives NULL-timestamp rows; only audit_log's NULLs are known-dead", s.table)
		}
	}
}

// A malformed override must not silently become an aggressive window.
func TestBadRetentionOverrideIsIgnoredNotCoerced(t *testing.T) {
	t.Setenv("RETENTION_USAGE_EVENTS_DAYS", "not-a-number")
	for _, s := range activeSpecs() {
		if s.table == "usage_events" {
			if got := s.retention.Hours() / 24; got != 35 {
				t.Errorf("bad override changed retention to %v days; want the 35-day default", got)
			}
			return
		}
	}
	t.Fatal("usage_events disappeared from the sweep on a malformed override")
}

// Zero or negative days would mean "delete everything older than now".
func TestNonPositiveRetentionOverrideIsRejected(t *testing.T) {
	for _, v := range []string{"0", "-5"} {
		t.Setenv("RETENTION_USAGE_EVENTS_DAYS", v)
		for _, s := range activeSpecs() {
			if s.table == "usage_events" && s.retention.Hours()/24 != 35 {
				t.Errorf("%s=%q yielded %v days; want the 35-day default", "RETENTION_USAGE_EVENTS_DAYS", v, s.retention.Hours()/24)
			}
		}
	}
}
