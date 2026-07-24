package common

// Minimal S3-compatible object store client (path-style, AWS SigV4).
// Configured via S3_SESSIONS_* env vars. If the endpoint is not set, Blobs
// is nil and all callers fall back to LONGBLOB storage (backward-compatible).

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Blobs is the global blobstore instance. nil = disabled (DB-only mode).
var Blobs *BlobStore

// BlobStore is a thin SigV4 S3 client for PUT/GET of gzip blobs.
type BlobStore struct {
	host   string // e.g. "objectstorage.eu-central-1.upcloudobjects.com"
	scheme string // "https" or "http"
	region string
	key    string
	secret string
	bucket string
	prefix string // always "claude-sessions/"
	client *http.Client
}

// InitBlobStore reads S3_SESSIONS_* env vars and initialises Blobs.
// Called once from main before the HTTP server starts.
func InitBlobStore() {
	raw := os.Getenv("S3_SESSIONS_ENDPOINT")
	if raw == "" {
		log.Print("blobstore: S3_SESSIONS_ENDPOINT not set — session blobs stored in DB")
		return
	}
	scheme := "https"
	host := strings.TrimPrefix(raw, "https://")
	if strings.HasPrefix(raw, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(raw, "http://")
	}
	host = strings.TrimRight(host, "/")

	region := os.Getenv("S3_SESSIONS_REGION")
	if region == "" {
		// Extract region from UpCloud hostnames:
		//   objectstorage.{region}.upcloudobjects.com → last segment before ".upcloudobjects.com"
		//   {region}.upcloudobjects.com              → the lone prefix
		if strings.HasSuffix(host, ".upcloudobjects.com") {
			core := strings.TrimSuffix(host, ".upcloudobjects.com")
			if idx := strings.LastIndex(core, "."); idx >= 0 {
				region = core[idx+1:]
			} else {
				region = core
			}
		} else {
			region = "auto"
		}
	}

	Blobs = &BlobStore{
		host:   host,
		scheme: scheme,
		region: region,
		key:    os.Getenv("S3_SESSIONS_KEY"),
		secret: os.Getenv("S3_SESSIONS_SECRET"),
		bucket: os.Getenv("S3_SESSIONS_BUCKET"),
		prefix: "claude-sessions/",
		client: &http.Client{Timeout: 30 * time.Second},
	}
	log.Printf("blobstore: s3 enabled bucket=%s region=%s prefix=%s", Blobs.bucket, region, Blobs.prefix)
}

// TurnBlobKey returns the S3 key prefix for a given conv_key + turn_index.
// Each turn has three blobs under this prefix: request_meta.gz, new_messages.gz, response.gz.
func TurnBlobKey(convKey string, turnIndex int) string {
	return fmt.Sprintf("%s/%d", convKey, turnIndex)
}

// Put stores data at claude-sessions/{relKey}.
func (b *BlobStore) Put(relKey string, data []byte) error {
	return b.s3do("PUT", b.prefix+relKey, data)
}

// Get retrieves data from claude-sessions/{relKey}.
func (b *BlobStore) Get(relKey string) ([]byte, error) {
	return b.s3get(b.prefix + relKey)
}

// ── SigV4 helpers ───────────────────────────────────────────────────────────

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacsha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (b *BlobStore) signingKey(date string) []byte {
	kDate := hmacsha256([]byte("AWS4"+b.secret), []byte(date))
	kRegion := hmacsha256(kDate, []byte(b.region))
	kService := hmacsha256(kRegion, []byte("s3"))
	return hmacsha256(kService, []byte("aws4_request"))
}

func (b *BlobStore) signedRequest(method, objKey string, body []byte) (*http.Request, error) {
	now := time.Now().UTC()
	dateTime := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	if body == nil {
		body = []byte{}
	}
	bodyHash := sha256hex(body)

	rawURL := fmt.Sprintf("%s://%s/%s/%s", b.scheme, b.host, b.bucket, objKey)

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Required headers — must be in canonical (sorted) order.
	req.Header.Set("x-amz-content-sha256", bodyHash)
	req.Header.Set("x-amz-date", dateTime)

	var canonHeaders, signedHeaders string
	if method == "PUT" {
		req.Header.Set("Content-Type", "application/octet-stream")
		canonHeaders = "content-type:application/octet-stream\nhost:" + b.host +
			"\nx-amz-content-sha256:" + bodyHash + "\nx-amz-date:" + dateTime + "\n"
		signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date"
	} else {
		canonHeaders = "host:" + b.host +
			"\nx-amz-content-sha256:" + bodyHash + "\nx-amz-date:" + dateTime + "\n"
		signedHeaders = "host;x-amz-content-sha256;x-amz-date"
	}

	canonPath := "/" + b.bucket + "/" + objKey
	canonReq := method + "\n" + canonPath + "\n\n" + canonHeaders + "\n" + signedHeaders + "\n" + bodyHash

	credScope := date + "/" + b.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + dateTime + "\n" + credScope + "\n" + sha256hex([]byte(canonReq))

	sig := hex.EncodeToString(hmacsha256(b.signingKey(date), []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		b.key, credScope, signedHeaders, sig))

	return req, nil
}

func (b *BlobStore) s3do(method, objKey string, body []byte) error {
	req, err := b.signedRequest(method, objKey, body)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 %s %s: %d %s", method, objKey, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

func (b *BlobStore) s3get(objKey string) ([]byte, error) {
	req, err := b.signedRequest("GET", objKey, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("not found: %s", objKey)
	}
	if resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("s3 GET %s: %d %s", objKey, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return io.ReadAll(resp.Body)
}
