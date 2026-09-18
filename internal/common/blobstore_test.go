package common

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testBlobStore points a BlobStore at an httptest server standing in for S3.
func testBlobStore(t *testing.T, srv *httptest.Server) *BlobStore {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &BlobStore{
		host:   u.Host,
		scheme: u.Scheme,
		region: "auto",
		key:    "test-key",
		secret: "test-secret",
		bucket: "test-bucket",
		prefix: "claude-sessions/",
		client: srv.Client(),
	}
}

// The regression this pins: DELETE /claude-sessions/:conv used to remove only
// the DB rows, because BlobStore had no Delete method at all — the S3 content
// was permanently orphaned. This confirms Delete issues a real DELETE against
// the correct prefixed key.
func TestDeleteIssuesRealS3Delete(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	b := testBlobStore(t, srv)
	if err := b.Delete("conv123/0/request_meta.gz"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	wantPath := "/test-bucket/claude-sessions/conv123/0/request_meta.gz"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
}

// S3 DELETE on an already-gone (or never-existed) key returns 404, and that
// must NOT surface as an error — otherwise a retry, or a turn that fell back
// to DB storage on PUT (see putTurnBlobs' degrade path) and so was never
// written to S3 in the first place, would make session deletion look like it
// failed when there was nothing wrong.
func TestDeleteToleratesAlreadyGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	b := testBlobStore(t, srv)
	if err := b.Delete("conv123/0/request_meta.gz"); err != nil {
		t.Errorf("Delete on a 404 should not error, got: %v", err)
	}
}

// A genuine server-side failure (not 404) must still surface — silently
// swallowing every non-2xx would defeat the whole point of counting blob
// deletion failures back to the caller in deleteSession.
func TestDeleteSurfacesRealFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	b := testBlobStore(t, srv)
	if err := b.Delete("conv123/0/request_meta.gz"); err == nil {
		t.Error("Delete on a 500 should return an error")
	}
}

func TestDeleteAppliesThePrefixLikePutAndGet(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	b := testBlobStore(t, srv)
	_ = b.Delete("x/y/z.gz")
	if !strings.HasSuffix(gotPath, "claude-sessions/x/y/z.gz") {
		t.Errorf("Delete did not apply the claude-sessions/ prefix: got path %q", gotPath)
	}
}

// Archives must NOT land under the live session-blob prefix. If PutArchive ever
// routed through Put's claude-sessions/ prefix, a session delete walking that
// prefix could remove the only surviving copy of swept rows — the DB rows are
// gone by then. This pins the separation rather than trusting the constant.
func TestPutArchiveUsesArchivePrefixNotSessionPrefix(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := testBlobStore(t, srv)
	if err := b.PutArchive("usage_events/20260915T120000Z-1-5000.ndjson.gz", []byte("x")); err != nil {
		t.Fatalf("PutArchive: %v", err)
	}
	if gotMethod != "PUT" {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if !strings.Contains(gotPath, "/archive/") {
		t.Errorf("path %q does not carry the archive/ prefix", gotPath)
	}
	if strings.Contains(gotPath, "claude-sessions") {
		t.Fatalf("archive written under the LIVE session prefix: %q — a session "+
			"delete sweeping that prefix would destroy archived rows", gotPath)
	}

	// Positive control: the same store must still put session blobs under
	// claude-sessions/, so the assertion above is discriminating and not just
	// passing because nothing is prefixed at all.
	if err := b.Put("conv/0/response.gz", []byte("y")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.Contains(gotPath, "claude-sessions/") {
		t.Errorf("Put path = %q, want the claude-sessions/ prefix", gotPath)
	}
}
