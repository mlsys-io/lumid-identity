package handler

// me_agent tool: generate_image + text_to_speech.
//
// These wrap the in-cluster lumid-llm gateway's multimodal endpoints
// (/v1/images/generations → qwen-image via ComfyUI; /v1/audio/speech →
// qwen-tts via CosyVoice2) so the Studio chat can PRODUCE images and
// speech, not just read them. The generated media is persisted as a
// first-class artifact under the caller's tenant (kind=image|audio,
// content = a self-contained data: URL) so the Studio artifact panel
// renders it inline and it outlives the chat turn. The tool return
// value handed back to the model is a SMALL reference ({id,kind,url,…})
// — never the base64 payload, which would blow the context window and
// teach the model nothing.

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
	// artifactMaxMedia — image/audio artifacts are much larger than the
	// text kinds (a 1024² PNG data URL runs ~1–3 MB); give them their own
	// ceiling instead of the 256 KB text cap.
	artifactMaxMedia = 12 * 1024 * 1024

	mediaModelImage = "qwen-image"
	mediaModelTTS   = "qwen-tts"
)

// mediaToolDefs advertises the media-generation tools. Available to every
// role — the gateway is free local GPU and the output lands in the caller's
// own tenant artifact store (no cross-tenant surface).
func mediaToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name": "generate_image",
			"description": "Generate an IMAGE from a text prompt (qwen-image on the Lumid GPU). " +
				"Use when the user asks you to draw, create, render, or generate a picture/logo/diagram. " +
				"The image is saved to the user's artifact panel and shown inline; you get back a small " +
				"reference (id + url), NOT the pixels. Confirm in one line what you made.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"prompt": map[string]any{"type": "string", "description": "what to depict (be descriptive)"},
					"size":   map[string]any{"type": "string", "description": "WxH, e.g. 1024x1024 (default), 512x512, 1280x720"},
				},
				"required": []string{"prompt"},
			},
		},
		{
			"name": "text_to_speech",
			"description": "Synthesize SPEECH audio from text (qwen-tts / CosyVoice2 on the Lumid GPU). " +
				"Use when the user asks you to read something aloud, narrate, or produce a voice/audio clip. " +
				"The audio is saved to the artifact panel and shown with a player; you get back a small " +
				"reference (id + url), NOT the audio bytes.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{"type": "string", "description": "the text to speak"},
					"voice": map[string]any{"type": "string", "description": "voice id (optional; default)"},
				},
				"required": []string{"input"},
			},
		},
	}
}

// lumidLLMMediaPost POSTs to the lumid-llm gateway (base from lumidLLMBase())
// and returns the raw response body + content-type. Shared by the media tools.
func lumidLLMMediaPost(ctx context.Context, path string, body map[string]any) ([]byte, string, error) {
	key, err := kvrunPAT()
	if err != nil {
		return nil, "", err
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, lumidLLMBase()+path, bytes.NewReader(buf))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer r.Body.Close()
	respBody, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, "", fmt.Errorf("gateway %s %d: %s", path, r.StatusCode, string(respBody[:min(300, len(respBody))]))
	}
	return respBody, r.Header.Get("Content-Type"), nil
}

// persistMediaArtifact writes an image/audio artifact (data-URL content) for
// the caller via the shared DB-backed artifact store, with the larger media
// content ceiling. Returns the same small metadata shape as save_artifact.
func persistMediaArtifact(userID, kind, title, dataURL, srcTool string) (map[string]any, bool) {
	return persistArtifact(userID, artifact{
		Kind: kind, Title: strings.TrimSpace(title), Content: dataURL, SourceTool: srcTool,
	}, artifactMaxMedia)
}

// toolGenerateImage — generate_image tool handler.
func toolGenerateImage(ctx context.Context, userID string, args map[string]any) (map[string]any, bool) {
	prompt, _ := args["prompt"].(string)
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return map[string]any{"error": "prompt required"}, false
	}
	size, _ := args["size"].(string)
	if strings.TrimSpace(size) == "" {
		size = "1024x1024"
	}
	cctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	respBody, _, err := lumidLLMMediaPost(cctx, "/v1/images/generations", map[string]any{
		"model": mediaModelImage, "prompt": prompt, "size": size, "n": 1,
	})
	if err != nil {
		return map[string]any{"error": "image generation failed: " + err.Error()}, false
	}
	var parsed struct {
		Data []struct {
			B64JSON string `json:"b64_json"`
			URL     string `json:"url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil || len(parsed.Data) == 0 {
		return map[string]any{"error": "image generation returned no image"}, false
	}
	b64 := parsed.Data[0].B64JSON
	if b64 == "" {
		// Some backends return a URL instead of inline b64 — pass it through.
		if u := parsed.Data[0].URL; u != "" {
			return persistMediaArtifact(userID, "image", prompt, u, "generate_image")
		}
		return map[string]any{"error": "image generation returned empty payload"}, false
	}
	return persistMediaArtifact(userID, "image", prompt, "data:image/png;base64,"+b64, "generate_image")
}

// toolTextToSpeech — text_to_speech tool handler.
func toolTextToSpeech(ctx context.Context, userID string, args map[string]any) (map[string]any, bool) {
	input, _ := args["input"].(string)
	input = strings.TrimSpace(input)
	if input == "" {
		return map[string]any{"error": "input text required"}, false
	}
	voice, _ := args["voice"].(string)
	if strings.TrimSpace(voice) == "" {
		voice = "default"
	}
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	body := map[string]any{"model": mediaModelTTS, "input": input, "voice": voice}
	respBody, ctype, err := lumidLLMMediaPost(cctx, "/v1/audio/speech", body)
	if err != nil {
		return map[string]any{"error": "speech synthesis failed: " + err.Error()}, false
	}
	mime := "audio/mpeg"
	if strings.HasPrefix(ctype, "audio/") {
		mime = strings.Split(ctype, ";")[0]
	}
	b64 := base64.StdEncoding.EncodeToString(respBody)
	title := input
	if len(title) > 60 {
		title = title[:60] + "…"
	}
	return persistMediaArtifact(userID, "audio", title, "data:"+mime+";base64,"+b64, "text_to_speech")
}
