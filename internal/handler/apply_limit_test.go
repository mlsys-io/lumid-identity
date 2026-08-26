package handler

import "testing"

// Every case here is a shape that reached prod. The unanchored predecessor got
// the first four wrong: the two "unbounded" rows ran the OUTER query with no
// bound, and LIMIT ALL was turned into a syntax error.
func TestApplyLimit(t *testing.T) {
	const cap = 200
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no limit", "SELECT 1", "SELECT 1\nLIMIT 200"},
		{"already bounded", "SELECT * FROM t LIMIT 5", "SELECT * FROM t LIMIT 5"},
		{"limit with offset stays untouched",
			"SELECT * FROM t LIMIT 5 OFFSET 10", "SELECT * FROM t LIMIT 5 OFFSET 10"},

		// --- the regressions the old regex allowed ---
		{"subquery limit does not bound the outer query",
			"SELECT * FROM (SELECT x FROM t LIMIT 5) s",
			"SELECT * FROM (SELECT x FROM t LIMIT 5) s\nLIMIT 200"},
		{"limit inside a string literal is not a limit",
			"SELECT 'limit 5' AS s", "SELECT 'limit 5' AS s\nLIMIT 200"},
		{"limit inside a trailing comment is not a limit",
			"SELECT * FROM t -- limit 10", "SELECT * FROM t -- limit 10\nLIMIT 200"},
		{"LIMIT ALL is replaced, not appended to",
			"SELECT * FROM t LIMIT ALL", "SELECT * FROM t LIMIT 200"},
		{"LIMIT ALL with offset",
			"SELECT * FROM t LIMIT ALL OFFSET 3", "SELECT * FROM t LIMIT 200 OFFSET 3"},

		// --- shape/spacing ---
		{"trailing semicolon is dropped before appending",
			"SELECT 1;", "SELECT 1\nLIMIT 200"},
		{"case and whitespace insensitive", "SELECT * FROM t limit   5", "SELECT * FROM t limit   5"},
		{"newline before limit", "SELECT *\nFROM t\nLIMIT 5", "SELECT *\nFROM t\nLIMIT 5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := applyLimit(c.in, cap); got != c.want {
				t.Errorf("applyLimit(%q)\n  got  %q\n  want %q", c.in, got, c.want)
			}
		})
	}
}

// The guard must never leave a query unbounded, whatever the input shape.
func TestApplyLimitAlwaysBounds(t *testing.T) {
	for _, in := range []string{
		"SELECT 1",
		"SELECT * FROM (SELECT x FROM t LIMIT 5) s",
		"SELECT 'limit 5' AS s",
		"SELECT * FROM t -- limit 10",
		"SELECT * FROM t LIMIT ALL",
		"SELECT * FROM t;",
	} {
		got := applyLimit(in, 200)
		if !limitTailRe.MatchString(trailingLineCommentRe.ReplaceAllString(got, "")) {
			t.Errorf("applyLimit(%q) = %q — still unbounded", in, got)
		}
	}
}
