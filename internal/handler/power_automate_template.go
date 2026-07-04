package handler

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /api/v1/me/power-automate-tokens/flow-template
//
// Returns a Power Automate "Solutionless package" (.zip) the user
// can import at make.powerautomate.com → My flows → Import → upload.
// The user's webhook URL is pre-baked into the HTTP action so post-
// import the user only needs to confirm the Outlook connection and
// save — no URL editing required.
//
// We mint a webhook token on demand if the user doesn't already have
// one (so the template is always self-sufficient — they don't need
// to visit the connect page first to set up the token).
//
// Package structure (the minimal one PA's import accepts):
//
//	manifest.json
//	Microsoft.Flow/flows/<guid>/definition.json
//	Microsoft.Flow/flows/<guid>/apisMap.json
func MePowerAutomateFlowTemplate(c *gin.Context) {
	userSub, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// Re-mint to ensure the user has a token. If they already have
	// one we DON'T rotate (rotating would break any existing flow);
	// we just hand back the existing URL. To find the existing URL
	// we'd need to know the raw token, which we don't persist —
	// only the hash. So this endpoint always mints fresh and the
	// user is told that importing the template rotates the webhook.
	rawTok, err := mintOrReuseWebhookToken(userSub)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "token mint: "+err.Error())
		return
	}

	scheme := "https"
	if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	if h := c.GetHeader("X-Forwarded-Proto"); h != "" {
		scheme = h
	}
	host := c.Request.Host
	if h := c.GetHeader("X-Forwarded-Host"); h != "" {
		host = h
	}
	webhookURL := fmt.Sprintf("%s://%s/api/v1/inbox/power-automate/%s", scheme, host, rawTok)

	pkg, err := buildPAPackage(webhookURL, userSub)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "package build: "+err.Error())
		return
	}

	filename := "lumid-outlook-bridge.zip"
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("X-Lumid-Webhook-Rotated", "1")
	c.Data(http.StatusOK, "application/zip", pkg)
}

// mintOrReuseWebhookToken returns a raw token. If no existing token
// exists for the user we create one and persist its hash. If one
// exists we still rotate (the caller's UI will surface a warning
// that rotation breaks any prior flow) — we can't reuse because
// only the hash is persisted, never the raw value.
func mintOrReuseWebhookToken(userSub string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)

	// Hash + persist (upsert).
	hashed := sha256Hex(tok)
	row := models.PowerAutomateToken{
		UserSub:   userSub,
		TokenHash: hashed,
		IssuedAt:  time.Now().UTC(),
	}
	if err := common.DB.Save(&row).Error; err != nil {
		return "", err
	}
	return tok, nil
}

// sha256Hex — local helper duplicating what's in power_automate.go.
// Tiny enough to avoid the cross-file dependency.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ── Package builder ───────────────────────────────────────────────

func buildPAPackage(webhookURL, userSub string) ([]byte, error) {
	// Stable-ish but per-user flow GUID. PA needs a GUID-shaped
	// identifier inside the package; we derive one from the user_sub
	// so re-downloads are idempotent. Anything 36-char "8-4-4-4-12"
	// is acceptable; PA assigns its own internally on import.
	flowGUID := guidFromUserSub(userSub)

	def := buildFlowDefinition(webhookURL)
	defBytes, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return nil, err
	}

	manifest := buildManifest(flowGUID)
	manBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	apisMap := buildApisMap()
	apisBytes, err := json.MarshalIndent(apisMap, "", "  ")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name string, content []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(content)
		return err
	}

	if err := addFile("manifest.json", manBytes); err != nil {
		return nil, err
	}
	if err := addFile(
		"Microsoft.Flow/flows/"+flowGUID+"/definition.json",
		defBytes,
	); err != nil {
		return nil, err
	}
	if err := addFile(
		"Microsoft.Flow/flows/"+flowGUID+"/apisMap.json",
		apisBytes,
	); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// guidFromUserSub — synthesize an 8-4-4-4-12 GUID from the user_sub
// (which is already a UUID). PA accepts any GUID-shaped string; the
// import process assigns its own internal IDs.
func guidFromUserSub(s string) string {
	if len(s) >= 36 && s[8] == '-' && s[13] == '-' {
		return s[:36]
	}
	// Fallback — pad with deterministic zeros.
	out := s + "00000000-0000-0000-0000-000000000000"
	return out[:36]
}

// ── Manifest ──────────────────────────────────────────────────────

func buildManifest(flowGUID string) map[string]any {
	return map[string]any{
		"schema": "1.0",
		"details": map[string]any{
			"displayName":        "Lumid Outlook Bridge",
			"description":        "Forwards new Outlook email to Lumid via webhook",
			"createdTime":        time.Now().UTC().Format(time.RFC3339),
			"packageTelemetryId": "lumid-outlook-bridge",
			"creator":            "Lumid",
			"sourceEnvironment":  "",
		},
		"resources": map[string]any{
			flowGUID: map[string]any{
				"id":                    nil,
				"name":                  flowGUID,
				"type":                  "Microsoft.Flow/flows",
				"suggestedCreationType": "New",
				"creationType":          "New",
				"details": map[string]any{
					"displayName": "Lumid Outlook Bridge",
				},
				"configurableBy": "User",
				"hierarchy":      "Root",
				"dependsOn":      []string{},
			},
		},
	}
}

// ── apisMap (connection references) ───────────────────────────────

func buildApisMap() map[string]any {
	// Maps the connection names used in the definition to the
	// canonical Office 365 connector. On import PA prompts the user
	// to bind this to their Outlook account.
	return map[string]any{
		"shared_office365": map[string]any{
			"apiId": "/providers/Microsoft.PowerApps/apis/shared_office365",
		},
	}
}

// ── Flow definition (the actual logic) ────────────────────────────

func buildFlowDefinition(webhookURL string) map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"displayName": "Lumid Outlook Bridge",
			"state":       "Started",
			"definition": map[string]any{
				"$schema":        "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
				"contentVersion": "1.0.0.0",
				"parameters": map[string]any{
					"$connections": map[string]any{
						"defaultValue": map[string]any{},
						"type":         "Object",
					},
					"$authentication": map[string]any{
						"defaultValue": map[string]any{},
						"type":         "SecureObject",
					},
				},
				"triggers": map[string]any{
					"When_a_new_email_arrives_(V3)": map[string]any{
						"type":    "OpenApiConnectionNotification",
						"splitOn": "@triggerOutputs()?['body/value']",
						"inputs": map[string]any{
							"host": map[string]any{
								"connectionName": "shared_office365",
								"operationId":    "OnNewEmailV3",
								"apiId":          "/providers/Microsoft.PowerApps/apis/shared_office365",
							},
							"parameters": map[string]any{
								"folderPath":              "Inbox",
								"importance":              "Any",
								"fetchOnlyWithAttachment": false,
								"includeAttachments":      false,
							},
							"authentication": map[string]any{
								"type":  "Raw",
								"value": "@json(decodeBase64(triggerOutputs().headers['X-MS-APIM-Tokens']))",
							},
						},
					},
				},
				"actions": map[string]any{
					"HTTP_to_Lumid": map[string]any{
						"type":     "Http",
						"runAfter": map[string]any{},
						"inputs": map[string]any{
							"method": "POST",
							"uri":    webhookURL,
							"headers": map[string]any{
								"Content-Type": "application/json",
							},
							"body": map[string]any{
								"id":          "@{triggerOutputs()?['body/id']}",
								"from":        "@{triggerOutputs()?['body/from']}",
								"to":          "@{triggerOutputs()?['body/to']}",
								"subject":     "@{triggerOutputs()?['body/subject']}",
								"body":        "@{triggerOutputs()?['body/bodyPreview']}",
								"html":        "@{triggerOutputs()?['body/body']}",
								"received_at": "@{triggerOutputs()?['body/receivedDateTime']}",
							},
						},
					},
				},
				"outputs": map[string]any{},
			},
		},
		"schemaVersion": "1.0.0.0",
	}
}
