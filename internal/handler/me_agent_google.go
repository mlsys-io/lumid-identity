package handler

// me_agent tools: send_email + create_calendar_event.
//
// Both reuse the user's existing Gmail+Calendar Google OAuth grant
// (server-mediated, refresh-token encrypted in the google_grants
// table — see CLAUDE.md "Google OAuth for apps"). Each tool call
// mints a fresh access-token via mintGoogleAccessToken() and shells
// out to the Gmail / Calendar API directly. No per-call user prompt;
// the grant is consented once at /dashboard/account/connect/google.
//
// When the user hasn't connected Google yet, both tools return a
// clean error pointing them at the connect page.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	gmailSendEndpoint    = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
	calendarBaseEndpoint = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
	googleAPITimeout     = 20 * time.Second
)

// toolSendEmail composes + sends an RFC 822 message via the user's
// Gmail account. To/Cc accept either a comma-separated string or a
// JSON array; Anthropic tool input arrives as `any`.
func toolSendEmail(userID string, args map[string]any) (map[string]any, bool) {
	to := normaliseAddressList(args["to"])
	cc := normaliseAddressList(args["cc"])
	bcc := normaliseAddressList(args["bcc"])
	subject, _ := args["subject"].(string)
	body, _ := args["body"].(string)
	subject = strings.TrimSpace(subject)
	body = strings.TrimSpace(body)
	if to == "" {
		return map[string]any{"error": "to required"}, false
	}
	if subject == "" {
		return map[string]any{"error": "subject required"}, false
	}
	if body == "" {
		return map[string]any{"error": "body required"}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), googleAPITimeout)
	defer cancel()
	token, err := mintGoogleAccessToken(ctx, userID)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}

	// Compose the RFC 822 message. Gmail's API requires a base64url-
	// encoded raw message; the API itself fills in From, Message-ID,
	// and Date based on the authenticated user.
	var headers []string
	headers = append(headers, "To: "+to)
	if cc != "" {
		headers = append(headers, "Cc: "+cc)
	}
	if bcc != "" {
		headers = append(headers, "Bcc: "+bcc)
	}
	headers = append(headers,
		"Subject: "+sanitizeHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	)
	raw := strings.Join(headers, "\r\n") + "\r\n\r\n" + body
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(raw))

	reqBody, _ := json.Marshal(map[string]any{"raw": encoded})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, gmailSendEndpoint, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"error": "gmail: " + err.Error()}, false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return map[string]any{"error": fmt.Sprintf("gmail %d: %s", resp.StatusCode, truncStr(string(respBody), 200))}, false
	}
	var out struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
	}
	_ = json.Unmarshal(respBody, &out)
	return map[string]any{
		"ok":         true,
		"message_id": out.ID,
		"thread_id":  out.ThreadID,
		"to":         to,
		"subject":    subject,
	}, true
}

// toolCreateCalendarEvent inserts an event on the user's primary
// calendar. start / end accept ISO 8601 strings (with timezone) or
// pure date strings ("2026-05-29" → all-day). attendees accepts a
// comma-separated string or JSON array.
func toolCreateCalendarEvent(userID string, args map[string]any) (map[string]any, bool) {
	title, _ := args["title"].(string)
	start, _ := args["start"].(string)
	end, _ := args["end"].(string)
	description, _ := args["description"].(string)
	location, _ := args["location"].(string)
	timezone, _ := args["timezone"].(string)
	title = strings.TrimSpace(title)
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if title == "" {
		return map[string]any{"error": "title required"}, false
	}
	if start == "" {
		return map[string]any{"error": "start required (ISO 8601 datetime or YYYY-MM-DD)"}, false
	}
	if end == "" {
		return map[string]any{"error": "end required"}, false
	}
	if timezone == "" {
		timezone = "America/Los_Angeles" // matches the lumid-scheduler default
	}

	// Date-only inputs become all-day events; datetime inputs use
	// dateTime + timeZone. Google's API differentiates by which key
	// is present in the {start,end} struct.
	mkTime := func(s string) map[string]any {
		if isDateOnly(s) {
			return map[string]any{"date": s}
		}
		return map[string]any{"dateTime": s, "timeZone": timezone}
	}

	event := map[string]any{
		"summary":     title,
		"description": description,
		"location":    location,
		"start":       mkTime(start),
		"end":         mkTime(end),
	}
	if att := normaliseAddressList(args["attendees"]); att != "" {
		list := make([]map[string]string, 0)
		for _, e := range strings.Split(att, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				list = append(list, map[string]string{"email": e})
			}
		}
		if len(list) > 0 {
			event["attendees"] = list
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), googleAPITimeout)
	defer cancel()
	token, err := mintGoogleAccessToken(ctx, userID)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}

	reqBody, _ := json.Marshal(event)
	// sendUpdates=all so any attendees receive invitations.
	endpoint := calendarBaseEndpoint + "?sendUpdates=all"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"error": "calendar: " + err.Error()}, false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return map[string]any{"error": fmt.Sprintf("calendar %d: %s", resp.StatusCode, truncStr(string(respBody), 200))}, false
	}
	var out struct {
		ID      string `json:"id"`
		HTMLink string `json:"htmlLink"`
		Status  string `json:"status"`
	}
	_ = json.Unmarshal(respBody, &out)
	return map[string]any{
		"ok":       true,
		"event_id": out.ID,
		"link":     out.HTMLink,
		"status":   out.Status,
		"title":    title,
		"start":    start,
		"end":      end,
	}, true
}

// normaliseAddressList accepts a comma-separated string OR a JSON
// array of strings and emits a canonical "a@x.com, b@y.com" form.
func normaliseAddressList(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// sanitizeHeader strips CR + LF so a malicious subject can't inject
// extra headers. Defensive even though tool args come from the LLM,
// not directly from user input.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// isDateOnly returns true for "YYYY-MM-DD" — used to decide between
// Google's `date` and `dateTime` start/end shapes.
func isDateOnly(s string) bool {
	if len(s) != 10 {
		return false
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return true
	}
	return false
}
