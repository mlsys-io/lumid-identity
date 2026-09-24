package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scheduled loop that documents an `Args:` contract is chat-invokable and
// must reach the prompt; a scheduled loop without one must not. quant-research's
// `backtest` (cron `5 */2 * * *`) was filtered out, so "backtest X on symbol Y"
// reached a model with no grammar for run_loop_now's args.
func TestAppVerbsHintIncludesScheduledLoopsWithArgs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	dir := filepath.Join(home, ".xp", "apps", "qr")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := `loops:
- name: send_strategy
  schedule: '@trigger'
  description: 'Deploy a strategy. Grammar here.'
- name: backtest
  schedule: '5 */2 * * *'
  description: 'Replay a strategy. Args: action, strategy_id, symbol.'
- name: harvest_outbox
  schedule: '0 * * * *'
  description: 'Internal housekeeping, no user args.'
`
	if err := os.WriteFile(filepath.Join(dir, "xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	got := appVerbsHint("sub", "qr")
	if !strings.Contains(got, "## send_strategy\n") {
		t.Fatalf("trigger loop missing:\n%s", got)
	}
	if !strings.Contains(got, "## backtest (also runs on a schedule") {
		t.Fatalf("scheduled loop with Args: missing:\n%s", got)
	}
	if strings.Contains(got, "harvest_outbox") {
		t.Fatalf("scheduled loop without Args: leaked into the prompt:\n%s", got)
	}
	if strings.Index(got, "send_strategy") > strings.Index(got, "backtest") {
		t.Fatalf("trigger loops must come first so their grammar survives the cap:\n%s", got)
	}
}
