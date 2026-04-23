package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/classifier"
	"github.com/limbic-systems/stargate/internal/server"
)

// postTest is a small helper that POSTs a JSON body to /test and returns the recorder.
func postTest(t *testing.T, srv *server.Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestTest_SameSchemaAsClassify verifies that /test returns the same response
// schema as /classify for identical input.
func TestTest_SameSchemaAsClassify(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	body := `{"command": "ls -la"}`

	wTest := postTest(t, srv, body)
	if wTest.Code != http.StatusOK {
		t.Fatalf("/test status = %d, want 200 (body=%s)", wTest.Code, wTest.Body.String())
	}

	req := httptest.NewRequest("POST", "/classify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	wClassify := httptest.NewRecorder()
	srv.ServeHTTP(wClassify, req)
	if wClassify.Code != http.StatusOK {
		t.Fatalf("/classify status = %d, want 200", wClassify.Code)
	}

	// Both responses should decode as ClassifyResponse without error.
	var tResp, cResp classifier.ClassifyResponse
	if err := json.Unmarshal(wTest.Body.Bytes(), &tResp); err != nil {
		t.Fatalf("/test response not valid ClassifyResponse: %v", err)
	}
	if err := json.Unmarshal(wClassify.Body.Bytes(), &cResp); err != nil {
		t.Fatalf("/classify response not valid ClassifyResponse: %v", err)
	}

	// Decisions should match (same command, same rules).
	if tResp.Decision != cResp.Decision {
		t.Errorf("decision mismatch: test=%q classify=%q", tResp.Decision, cResp.Decision)
	}
	if tResp.Action != cResp.Action {
		t.Errorf("action mismatch: test=%q classify=%q", tResp.Action, cResp.Action)
	}
}

// TestTest_ASTAlwaysPopulated verifies /test always includes ast in the response.
func TestTest_ASTAlwaysPopulated(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{"command": "ls"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp classifier.ClassifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AST == nil {
		t.Error("AST should always be populated on /test")
	}
}

// TestTest_NoFeedbackToken verifies /test never returns a feedback token,
// even for YELLOW decisions that would normally generate one.
func TestTest_NoFeedbackToken(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	// curl is a YELLOW rule; with tool_use_id present, /classify would return a token.
	body := `{"command": "curl https://example.com", "context": {"tool_use_id": "toolu_abc"}}`

	w := postTest(t, srv, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	var resp classifier.ClassifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FeedbackToken != nil {
		t.Errorf("FeedbackToken should be nil on /test, got %q", *resp.FeedbackToken)
	}
}

// TestTest_UseCacheTrue verifies use_cache=true is accepted on /test.
func TestTest_UseCacheTrue(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{"command": "ls", "use_cache": true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
}

// TestTest_UseCacheDefault verifies use_cache defaults to false without error.
func TestTest_UseCacheDefault(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{"command": "ls"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
}

// TestTest_DryRunFieldRejectedFromJSON verifies that sending "dry_run": true
// in the JSON body is rejected — the field has json:"-" tag on ClassifyRequest
// embedded in TestRequest, so DisallowUnknownFields rejects unknown keys.
func TestTest_DryRunFieldRejectedFromJSON(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	// dry_run is not a known field on TestRequest — should be rejected.
	w := postTest(t, srv, `{"command": "ls", "dry_run": true}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (dry_run should not be accepted, body=%s)", w.Code, w.Body.String())
	}
}

// TestClassify_UseCacheRejected verifies use_cache sent to /classify returns 400.
// ClassifyRequest.UseCache has a json:"-" tag, so DisallowUnknownFields
// treats use_cache as an unknown key and rejects the request.
func TestClassify_UseCacheRejected(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	req := httptest.NewRequest("POST", "/classify", bytes.NewBufferString(`{"command": "ls", "use_cache": true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (use_cache should not be on /classify)", w.Code)
	}
}

// TestTest_MissingCommand verifies /test rejects empty command.
func TestTest_MissingCommand(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{"command": ""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestTest_MalformedJSON verifies /test rejects malformed JSON.
func TestTest_MalformedJSON(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestTest_UnknownField verifies /test rejects unknown fields besides the
// allowed ones (command, cwd, description, context, use_cache).
func TestTest_UnknownField(t *testing.T) {
	srv := mustNewServer(t, testConfig())

	w := postTest(t, srv, `{"command": "ls", "unknown_field": "x"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown field", w.Code)
	}
}

// TestTest_CorpusNotWritten_ServerLayer is a shallow end-to-end check that
// the /test route doesn't report a corpus write in the response. The deeper
// regression coverage (LLM-mock + real corpus write path would fire in
// non-dry-run mode) lives in classifier TestDryRun_CorpusNotWrittenWithLLMAllow.
// Kept here as a smoke test that the HTTP handler doesn't inadvertently
// clear DryRun before calling Classify.
func TestTest_CorpusNotWritten_ServerLayer(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := testConfig()
	trueVal := true
	cfg.Corpus.Enabled = &trueVal
	cfg.Corpus.Path = tmpDir + "/corpus.db"

	srv := mustNewServer(t, cfg)

	w := postTest(t, srv, `{"command": "curl https://example.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("/test status = %d (body=%s)", w.Code, w.Body.String())
	}

	var resp classifier.ClassifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Corpus != nil && resp.Corpus.EntryWritten {
		t.Error("/test must not write to the corpus (EntryWritten=true)")
	}
}

// TestTest_ResponseContainsVersion verifies /test response has Version (schema smoke test).
func TestTest_ResponseContainsVersion(t *testing.T) {
	srv := mustNewServer(t, testConfig())
	w := postTest(t, srv, `{"command": "ls"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["version"]; !ok {
		t.Error("/test response missing version field")
	}
}

// TestTest_ContentType verifies /test returns application/json.
func TestTest_ContentType(t *testing.T) {
	srv := mustNewServer(t, testConfig())
	w := postTest(t, srv, `{"command": "ls"}`)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
