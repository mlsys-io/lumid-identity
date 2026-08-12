package handler

// Conversation summary titles for the Studio sidebar's "Recent" list.
//
// A Recent row is only useful if it says what the conversation was ABOUT.
// inferTitle() truncates the first user message, which is what a row showed
// before this: fine for "how do I rotate the LB cert", useless when the
// message opens with a pasted stack trace, a file path, or "hey quick q".
//
// The shape here is deliberately two-stage:
//
//  1. inferTitle() still runs synchronously on every save, so a row NEVER
//     renders blank or "Untitled chat" while a model is thinking. A save
//     path that blocks on an LLM would also make every turn slower for a
//     cosmetic feature, which is the wrong trade in the token authority.
//  2. Once the thread has an assistant reply to summarize, a background
//     goroutine asks the in-cluster gateway for a short title and rewrites
//     it in place. That is marked with `title_summary`, which both stops it
//     regenerating on later saves and stops inferTitle clobbering it back to
//     the truncated first message.
//
// Model is the default provider (Gemma-4 on the Lumid GPU via lumid-llm):
// free local compute, dailyBudgetTokens -1, so titling costs nothing and
// never competes with a user's Claude quota.

import (
	"context"
	"errors"
	"log"
	"lumid_identity/internal/common"
	"lumid_identity/models"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Shorter than chatTitleMaxLen (60): a generated title should be a label,
	// not a sentence, and the sidebar truncates anything longer anyway.
	chatTitleSummaryMaxLen = 48
	// Excerpt caps keep the prompt small — a title needs the topic, not the
	// whole transcript, and the first exchange carries the topic.
	chatTitleExcerptMax = 1200
	// Generous vs. the ~8 tokens of output actually wanted: the default
	// provider is a reasoning model and spends most of its budget on thinking
	// blocks, which are discarded. Too small a cap yields zero text blocks.
	chatTitleMaxTokens = 512
	chatTitleTimeout   = 45 * time.Second
)

// chatFileMu serialises read-modify-write on chat files. The title goroutine
// lands AFTER the save that spawned it, so without this it could resurrect a
// stale transcript by writing back a record it read before a newer save.
// One global lock rather than per-chat striping: chat writes are short and
// infrequent, and a map of locks would need its own eviction to not leak.
var chatFileMu sync.Mutex

// chatTitleInFlight stops N saves in one turn from spawning N generations for
// the same thread. Keyed userID+"\x00"+chatID.
var (
	chatTitleInFlightMu sync.Mutex
	chatTitleInFlight   = map[string]bool{}
)

const chatTitleSystemPrompt = `You write short titles for chat conversations.

Given the opening exchange of a conversation, reply with ONLY a title for it.

Rules:
- At most 6 words.
- Describe the topic or the task, not the fact that it is a conversation.
- No quotes, no trailing period, no prefix like "Title:".
- Match the language the user wrote in.
- If the exchange is too short or empty to have a topic, reply exactly: none`

// chatTitleSummaryEnabled is the kill switch. Set LUMID_CHAT_TITLE_SUMMARY=0
// to fall back to plain truncation without a redeploy.
func chatTitleSummaryEnabled() bool {
	return strings.TrimSpace(os.Getenv("LUMID_CHAT_TITLE_SUMMARY")) != "0"
}

// chatMessageText flattens a message's content to plain text. The frontend sends
// content as a string, but tool-bearing turns can send Anthropic-style block
// arrays, and a title should read the text either way.
func chatMessageText(m map[string]any) string {
	switch v := m["content"].(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, blk := range v {
			b, _ := blk.(map[string]any)
			if b == nil || b["type"] != "text" {
				continue // skip tool_use / tool_result / thinking
			}
			if t, ok := b["text"].(string); ok && t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// chatTitleExcerpt builds the prompt body: the first user message and the
// first assistant reply. Returns ok=false when there is no assistant reply
// yet — a lone user message is exactly what inferTitle already handles, so
// there is nothing a model would add.
func chatTitleExcerpt(msgs []map[string]any) (string, bool) {
	var user, assistant string
	for _, m := range msgs {
		role, _ := m["role"].(string)
		txt := strings.TrimSpace(chatMessageText(m))
		if txt == "" {
			continue
		}
		if role == "user" && user == "" {
			user = txt
		} else if role == "assistant" && assistant == "" {
			assistant = txt
		}
		if user != "" && assistant != "" {
			break
		}
	}
	if user == "" || assistant == "" {
		return "", false
	}
	return "User:\n" + truncateRunes(user, chatTitleExcerptMax) +
		"\n\nAssistant:\n" + truncateRunes(assistant, chatTitleExcerptMax), true
}

// cleanChatTitle normalises whatever the model returned into a single-line
// label, or "" if it is unusable. Models reliably ignore at least one of the
// formatting rules, so none of this is defensive theatre.
func cleanChatTitle(raw string) string {
	t := strings.TrimSpace(raw)
	// First non-empty line — drops any preamble or trailing commentary.
	for _, line := range strings.Split(t, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			t = s
			break
		}
	}
	t = strings.TrimSpace(strings.TrimPrefix(t, "Title:"))
	t = strings.Trim(t, " \t\"'“”‘’`")
	t = strings.TrimRight(t, ".。")
	t = strings.Join(strings.Fields(t), " ")
	if t == "" || strings.EqualFold(t, "none") {
		return ""
	}
	return truncateRunes(t, chatTitleSummaryMaxLen)
}

// setChatTitle rewrites just the title of an already-persisted chat.
// Re-reads under the lock so it never writes back a stale transcript, and
// yields to a title already generated by a concurrent pass.
func setChatTitle(userID, chatID, title string) error {
	chatFileMu.Lock()
	defer chatFileMu.Unlock()

	rec, err := chatStoreGet(userID, chatID)
	if err != nil {
		return err // deleted mid-flight is a normal outcome, not an error to fix
	}
	if rec.TitleSummary {
		return nil
	}
	rec.Title = title
	rec.TitleSummary = true
	if err := chatStoreSave(userID, rec); err != nil {
		return err
	}
	return nil
}

// maybeSummarizeChatTitle spawns title generation if this thread still has a
// truncated title and now has something to summarize. Safe to call on every
// save; it is a no-op in the common case.
func maybeSummarizeChatTitle(userID, chatID string, msgs []map[string]any) {
	if !chatTitleSummaryEnabled() {
		return
	}
	excerpt, ok := chatTitleExcerpt(msgs)
	if !ok {
		return
	}
	key := userID + "\x00" + chatID
	chatTitleInFlightMu.Lock()
	if chatTitleInFlight[key] {
		chatTitleInFlightMu.Unlock()
		return
	}
	chatTitleInFlight[key] = true
	chatTitleInFlightMu.Unlock()

	go func() {
		defer func() {
			chatTitleInFlightMu.Lock()
			delete(chatTitleInFlight, key)
			chatTitleInFlightMu.Unlock()
		}()
		if err := generateChatTitle(userID, chatID, excerpt); err != nil {
			// Not user-visible: the truncated title stays, which is the
			// pre-existing behaviour. Logged because a persistent failure
			// here means the gateway or its PAT is misconfigured.
			log.Printf("chat-title: %s/%s: %v", userID, chatID, err)
		}
	}()
}

func generateChatTitle(userID, chatID, excerpt string) error {
	provider := defaultProvider()
	apiKey, err := provider.keyFn()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), chatTitleTimeout)
	defer cancel()

	resp, err := callLLM(ctx, provider, apiKey, map[string]any{
		"model":      provider.upstreamModel,
		"max_tokens": chatTitleMaxTokens,
		"system":     chatTitleSystemPrompt,
		"messages":   []map[string]any{{"role": "user", "content": excerpt}},
	})
	if err != nil {
		return err
	}

	var text strings.Builder
	content, _ := resp["content"].([]any)
	for _, blk := range content {
		b, _ := blk.(map[string]any)
		if b == nil || b["type"] != "text" {
			continue // discard thinking blocks
		}
		if t, ok := b["text"].(string); ok {
			text.WriteString(t)
		}
	}
	title := cleanChatTitle(text.String())
	if title == "" {
		return errors.New("model returned no usable title")
	}
	return setChatTitle(userID, chatID, title)
}

// disambiguateChatTitle appends an ordinal when a user already has a DIFFERENT
// thread by the same name.
//
// Both title stages derive from the opening exchange, and an app that starts
// every thread from one templated prompt ("Let's work case X. Give me the
// opening.") therefore produces identical titles by construction. In the
// sidebar that reads as one conversation duplicated N times — the rail's whole
// job is telling threads apart.
//
// Ordinal, not a timestamp: the row already shows a relative age, and two
// facts competing for ~14 characters leaves neither legible.
func disambiguateChatTitle(userSub, chatID, title string) string {
	if common.DB == nil || title == "" || userSub == "" {
		return title
	}
	var clash int64
	if err := common.DB.Model(&models.MeChat{}).
		Where("user_sub = ? AND title = ? AND id <> ?", userSub, title, chatID).
		Count(&clash).Error; err != nil || clash == 0 {
		return title
	}
	// Find the first free ordinal rather than using count+1: threads get
	// deleted, and reusing a freed number is better than skipping to " · 7"
	// because six were removed.
	for n := 2; n <= 99; n++ {
		cand := title + " · " + strconv.Itoa(n)
		var taken int64
		if err := common.DB.Model(&models.MeChat{}).
			Where("user_sub = ? AND title = ? AND id <> ?", userSub, cand, chatID).
			Count(&taken).Error; err != nil {
			return title
		}
		if taken == 0 {
			return cand
		}
	}
	return title
}
