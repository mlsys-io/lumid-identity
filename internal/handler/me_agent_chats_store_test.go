package handler

// toRow/fromRow round-trip.
//
// This exists because of a bug that was invisible from every direction that
// looked authoritative. MeChatSave accepted `strategy_id` and returned 200,
// chatRecord carried the field, MeChatsList marshalled it, the UI latched it
// and sent it, and the per-strategy Sessions table filtered on it — but
// toRow() never copied it into models.MeChat, so MySQL never saw it and the
// list echoed nothing back. The table fails closed on an unmatched id, so the
// only symptom was an empty Sessions table: no error, no log line, no failing
// request. Reading any single layer confirmed the feature worked.
//
// So this asserts the flatteners preserve EVERY field, by reflection rather
// than by a list someone has to remember to extend — a field added to
// chatRecord and forgotten in toRow fails here instead of shipping silent.
//
// No DB: the package's other DB tests skip without TEST_MYSQL_DSN, which is
// exactly the kind of quiet pass this bug already survived once.

import (
	"reflect"
	"testing"
)

func TestChatRowRoundTripPreservesEveryField(t *testing.T) {
	// Every field distinctly non-zero, so a dropped one reads as a zero value.
	in := &chatRecord{
		ID:              "chat-00000000000000ff",
		Title:           "a title",
		TitleSummary:    true,
		CreatedAt:       "2026-08-26T07:00:00Z",
		UpdatedAt:       "2026-08-26T07:30:00Z",
		Messages:        []map[string]any{{"role": "user", "content": "hi"}},
		Model:           "deepseek-v4-flash",
		Mode:            "agent",
		ClaudeSessionID: "sess-abc",
		App:             "lqt-mailbox",
		StrategyID:      "1ebefa18-324a-475b-86d8-66f85b462bdb",
	}

	row, err := toRow("user-sub-1", in)
	if err != nil {
		t.Fatalf("toRow: %v", err)
	}
	out := fromRow(row)

	// Field-by-field via reflection so a newly added field is covered without
	// touching this test.
	vIn, vOut := reflect.ValueOf(*in), reflect.ValueOf(*out)
	for i := 0; i < vIn.NumField(); i++ {
		name := vIn.Type().Field(i).Name
		gotIn, gotOut := vIn.Field(i).Interface(), vOut.Field(i).Interface()
		if !reflect.DeepEqual(gotIn, gotOut) {
			t.Errorf("field %s dropped or mangled by the row flatteners: sent %#v, got back %#v",
				name, gotIn, gotOut)
		}
	}

	// The one that actually broke, called out so a failure names the symptom.
	if out.StrategyID != in.StrategyID {
		t.Errorf("strategy_id lost in storage — the per-strategy Sessions table will render empty")
	}
	if row.UserSub != "user-sub-1" {
		t.Errorf("user_sub = %q, want user-sub-1", row.UserSub)
	}
	if row.MsgCount != 1 {
		t.Errorf("msg_count = %d, want 1", row.MsgCount)
	}
}
