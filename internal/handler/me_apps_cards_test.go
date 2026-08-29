package handler

// Regression tests for "delete agent / remove app doesn't work".
//
// On UKS the me_app_intents queue IS the install registry — identity sits on the
// service tier and cannot read the scheduler's RWO app PVC, so `onDisk` is empty
// and a `done` install row is the only thing that makes a card. The bug was that
// card synthesis scanned `action = "install"` alone: the picker archived every
// copy on disk, the row was left untouched, and the next poll regenerated the
// card. The app came back and delete looked broken.

import (
	"encoding/json"
	"testing"
	"time"

	"lumid_identity/models"
)

func intentRow(action, app, status string, ageMin int) models.MeAppIntent {
	var payload []byte
	if action == "uninstall" {
		payload, _ = json.Marshal(map[string]any{"app": app})
	} else {
		payload, _ = json.Marshal(map[string]any{"slug": "owner-sub/" + app})
	}
	return models.MeAppIntent{
		Action:    action,
		UserSub:   "user-A",
		Status:    status,
		Payload:   string(payload),
		Result:    `{"ok":true}`,
		CreatedAt: time.Now().Add(-time.Duration(ageMin) * time.Minute),
	}
}

func cardFor(cards []pendingCard, app string) *pendingCard {
	for i := range cards {
		if cards[i].name == app {
			return &cards[i]
		}
	}
	return nil
}

func TestCardsFromIntents(t *testing.T) {
	// rows are newest-first, matching the query's ORDER BY created_at DESC
	tests := []struct {
		name       string
		rows       []models.MeAppIntent
		wantCard   bool
		wantStatus string
	}{
		{
			name:       "installed app shows a ready card",
			rows:       []models.MeAppIntent{intentRow("install", "vlm", "done", 60)},
			wantCard:   true,
			wantStatus: "ready",
		},
		{
			// THE BUG: this returned a ready card, so the agent came back.
			name: "completed uninstall removes the card",
			rows: []models.MeAppIntent{
				intentRow("uninstall", "vlm", "done", 5),
				intentRow("install", "vlm", "done", 60),
			},
			wantCard: false,
		},
		{
			name: "in-flight uninstall hides the card optimistically",
			rows: []models.MeAppIntent{
				intentRow("uninstall", "vlm", "pending", 1),
				intentRow("install", "vlm", "done", 60),
			},
			wantCard: false,
		},
		{
			// Honesty: the app really is still installed, so keep it visible
			// and retryable rather than lying that it's gone.
			name: "FAILED uninstall keeps the card",
			rows: []models.MeAppIntent{
				intentRow("uninstall", "vlm", "failed", 5),
				intentRow("install", "vlm", "done", 60),
			},
			wantCard:   true,
			wantStatus: "ready",
		},
		{
			// Reinstall after delete must come back — newest wins in both
			// directions, not just uninstall-suppresses-install.
			name: "reinstall after uninstall shows the card again",
			rows: []models.MeAppIntent{
				intentRow("install", "vlm", "done", 1),
				intentRow("uninstall", "vlm", "done", 30),
				intentRow("install", "vlm", "done", 60),
			},
			wantCard:   true,
			wantStatus: "ready",
		},
		{
			name: "uninstall of one app does not hide another",
			rows: []models.MeAppIntent{
				intentRow("uninstall", "vlm", "done", 5),
				intentRow("install", "vlm", "done", 60),
				intentRow("install", "mbb-ai", "done", 90),
			},
			wantCard: false, // asserted for vlm; mbb-ai checked below
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cards := cardsFromIntents(tc.rows, map[string]bool{})
			got := cardFor(cards, "vlm")
			if tc.wantCard {
				if got == nil {
					t.Fatalf("expected a card for vlm, got none (%d cards)", len(cards))
				}
				if got.status != tc.wantStatus {
					t.Fatalf("status = %q, want %q", got.status, tc.wantStatus)
				}
				return
			}
			if got != nil {
				t.Fatalf("expected NO card for vlm, got status=%q", got.status)
			}
		})
	}

	t.Run("sibling app survives another app's uninstall", func(t *testing.T) {
		cards := cardsFromIntents([]models.MeAppIntent{
			intentRow("uninstall", "vlm", "done", 5),
			intentRow("install", "vlm", "done", 60),
			intentRow("install", "mbb-ai", "done", 90),
		}, map[string]bool{})
		if cardFor(cards, "mbb-ai") == nil {
			t.Fatal("mbb-ai card was wrongly suppressed by vlm's uninstall")
		}
	})
}

func TestIntentAppName(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		// The uninstall shape MeAppsUninstall writes. installAppName alone
		// returned "" here, so even a corrected query matched no name.
		{"uninstall payload", map[string]any{"app": "vlm"}, "vlm"},
		{"install slug", map[string]any{"slug": "owner/vlm"}, "vlm"},
		{"install as-rename wins", map[string]any{"slug": "owner/vlm", "as": "mine"}, "mine"},
		{"draft suffix stripped", map[string]any{"slug": "owner/vlm-draft"}, "vlm"},
		{"whitespace-only app", map[string]any{"app": "   "}, ""},
		{"empty payload", map[string]any{}, ""},
		{"nil payload", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := intentAppName(tc.payload); got != tc.want {
				t.Fatalf("intentAppName(%v) = %q, want %q", tc.payload, got, tc.want)
			}
		})
	}
}

// A FAILED install must not report an app the user still has as broken.
//
// Re-installing an already-present app fails by design ("app already installed
// at …; use a different --new-name or uninstall first"), which a user hits by
// clicking Install twice or re-installing for an update. Before this, the newer
// failure won outright: the card went `failed`, MeAppsList skipped the `ui:`
// backfill it only does for `ready` cards, and the Studio workspace lost the
// app's surfaces, sidebar label and icon while the app itself kept working.
func TestFailedReinstallDoesNotPoisonAnInstalledApp(t *testing.T) {
	failedRow := func(app string, ageMin int) models.MeAppIntent {
		r := intentRow("install", app, "failed", ageMin)
		r.Result = `{"ok":false,"error":"app already installed at /home/x/.xp/agents/` + app + `"}`
		return r
	}

	t.Run("older successful install wins over a redundant failure", func(t *testing.T) {
		cards := cardsFromIntents([]models.MeAppIntent{
			failedRow("quant-research", 1),
			intentRow("install", "quant-research", "done", 60),
		}, map[string]bool{})
		c := cardFor(cards, "quant-research")
		if c == nil {
			t.Fatal("no card emitted for an app that is installed")
		}
		if c.status != "ready" {
			t.Fatalf("status = %q, want \"ready\" — a redundant install must not mark a working app broken (err=%q)", c.status, c.err)
		}
	})

	t.Run("a genuinely first-time failure still reports failed", func(t *testing.T) {
		cards := cardsFromIntents([]models.MeAppIntent{
			failedRow("never-worked", 1),
		}, map[string]bool{})
		c := cardFor(cards, "never-worked")
		if c == nil || c.status != "failed" {
			t.Fatalf("card = %+v, want status \"failed\" — nothing older says this ever installed", c)
		}
	})

	t.Run("uninstall after the successful install still means gone", func(t *testing.T) {
		cards := cardsFromIntents([]models.MeAppIntent{
			failedRow("removed-app", 1),
			intentRow("uninstall", "removed-app", "done", 30),
			intentRow("install", "removed-app", "done", 60),
		}, map[string]bool{})
		if c := cardFor(cards, "removed-app"); c != nil && c.status == "ready" {
			t.Fatal("reported ready for an app uninstalled after its successful install")
		}
	})

	t.Run("a FAILED uninstall does not hide the install", func(t *testing.T) {
		u := intentRow("uninstall", "kept-app", "failed", 30)
		cards := cardsFromIntents([]models.MeAppIntent{
			failedRow("kept-app", 1), u,
			intentRow("install", "kept-app", "done", 60),
		}, map[string]bool{})
		c := cardFor(cards, "kept-app")
		if c == nil || c.status != "ready" {
			t.Fatalf("card = %+v, want \"ready\" — the uninstall failed, so the app is still there", c)
		}
	})
}
