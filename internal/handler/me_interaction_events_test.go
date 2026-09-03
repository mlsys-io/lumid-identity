package handler

import "testing"

// The closed vocabulary is the whole reason this table stays answerable. If an
// unknown action starts being accepted, it becomes a logging sink.
func TestInteractionVocabularyIsClosed(t *testing.T) {
	for _, a := range []string{"surface_view", "form_submit", "row_action", "nav"} {
		if !interactionActions[a] {
			t.Errorf("%q should be in the vocabulary", a)
		}
	}
	for _, a := range []string{"", "click", "pageview", "custom", "SURFACE_VIEW", "surface_view "} {
		if interactionActions[a] {
			t.Errorf("%q must NOT be accepted — the vocabulary is closed on purpose", a)
		}
	}
	if n := len(interactionActions); n != 4 {
		t.Errorf("vocabulary has %d entries; growing it should be deliberate", n)
	}
}

// clipCol must fit a column exactly: no ellipsis pushing it over, and no
// slicing through a UTF-8 rune (MySQL measures varchar in characters).
func TestClipColFitsTheColumn(t *testing.T) {
	if got := clipCol("  hello  ", 32); got != "hello" {
		t.Errorf("clipCol trim = %q", got)
	}
	long := ""
	for i := 0; i < 200; i++ {
		long += "x"
	}
	if got := clipCol(long, 128); len([]rune(got)) != 128 {
		t.Errorf("clipCol len = %d runes, want exactly 128", len([]rune(got)))
	}
	// Multi-byte: 200 runes of 3 bytes each. Byte-slicing would split one.
	wide := ""
	for i := 0; i < 200; i++ {
		wide += "界"
	}
	got := clipCol(wide, 128)
	if len([]rune(got)) != 128 {
		t.Errorf("clipCol wide = %d runes, want 128", len([]rune(got)))
	}
	for _, r := range got {
		if r == '�' {
			t.Fatal("clipCol split a UTF-8 rune")
		}
	}
	// The pre-existing clip() would overflow here — that is why this exists.
	if len(clip(long, 128)) <= 128 {
		t.Log("note: clip() no longer overflows; clipCol may be redundant")
	}
}
