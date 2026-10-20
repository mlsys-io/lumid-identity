package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lumid_identity/internal/common"
)

// fakeS3 is an in-memory S3 stand-in keyed by request path.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	deletes []string
	corrupt bool // GET returns altered bytes (verification-failure tests)
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	f := &fakeS3{objects: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			b, ok := f.objects[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if f.corrupt {
				b = append(append([]byte{}, b...), 'x')
			}
			w.Write(b)
		case http.MethodHead:
			if _, ok := f.objects[r.URL.Path]; !ok {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			f.objects[r.URL.Path] = b
		case http.MethodDelete:
			f.deletes = append(f.deletes, r.URL.Path)
			if _, ok := f.objects[r.URL.Path]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.objects, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// withStores points common.Blobs / common.ColdBlobs at the given servers via
// the real env-driven init (cold may be nil = no cold tier).
func withStores(t *testing.T, hot, cold *httptest.Server) {
	t.Helper()
	origHot, origCold := common.Blobs, common.ColdBlobs
	t.Cleanup(func() { common.Blobs, common.ColdBlobs = origHot, origCold })
	t.Setenv("S3_SESSIONS_ENDPOINT", hot.URL)
	t.Setenv("S3_SESSIONS_BUCKET", "hot")
	if cold != nil {
		t.Setenv("S3_SESSIONS_COLD_ENDPOINT", cold.URL)
		t.Setenv("S3_SESSIONS_COLD_BUCKET", "cold")
	} else {
		t.Setenv("S3_SESSIONS_COLD_ENDPOINT", "")
	}
	common.ColdBlobs = nil
	common.InitBlobStore()
}

func putTurn(f *fakeS3, bucket, blobKey string) {
	for _, s := range []string{"request_meta.gz", "new_messages.gz", "response.gz"} {
		f.objects["/"+bucket+"/claude-sessions/"+blobKey+"/"+s] = gzipBytes([]byte(`"` + s + `"`))
	}
}

// A turn moved to the cold tier must still open: the hot store 404s and the
// read is served from the cold one.
func TestGetTurnBlobsFallsBackToColdTier(t *testing.T) {
	hotF, hot := newFakeS3(t)
	coldF, cold := newFakeS3(t)
	withStores(t, hot, cold)
	putTurn(coldF, "cold", "convA/3")
	putTurn(hotF, "hot", "convA/4")

	meta, msgs, resp := getTurnBlobs("convA/3")
	if string(meta) != `"request_meta.gz"` || string(msgs) != `"new_messages.gz"` || string(resp) != `"response.gz"` {
		t.Fatalf("cold turn not read back: %q %q %q", meta, msgs, resp)
	}
	if _, _, resp := getTurnBlobs("convA/4"); string(resp) != `"response.gz"` {
		t.Fatalf("hot turn not read: %q", resp)
	}
}

// Without a cold tier configured, a missing blob is simply missing.
func TestGetTurnBlobsWithoutColdTier(t *testing.T) {
	_, hot := newFakeS3(t)
	withStores(t, hot, nil)
	if meta, _, _ := getTurnBlobs("gone/0"); meta != nil {
		t.Fatalf("expected nil for a missing blob, got %q", meta)
	}
}

// Erasure must reach the cold tier, or deleting a session would leave its
// moved turns behind on the NAS.
func TestDeleteTurnBlobsErasesBothTiers(t *testing.T) {
	hotF, hot := newFakeS3(t)
	coldF, cold := newFakeS3(t)
	withStores(t, hot, cold)
	putTurn(coldF, "cold", "convB/0")
	putTurn(hotF, "hot", "convB/1")

	if failed := deleteTurnBlobs("convB/0"); failed != 0 {
		t.Fatalf("cold turn delete failed=%d", failed)
	}
	if failed := deleteTurnBlobs("convB/1"); failed != 0 {
		t.Fatalf("hot turn delete failed=%d", failed)
	}
	if len(hotF.objects) != 0 || len(coldF.objects) != 0 {
		t.Fatalf("objects left behind: hot=%v cold=%v", hotF.objects, coldF.objects)
	}
	for _, d := range coldF.deletes {
		if !strings.HasPrefix(d, "/cold/claude-sessions/") {
			t.Fatalf("cold delete hit wrong key %q", d)
		}
	}
}
