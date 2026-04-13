package feedback

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleFeedbackValidHMAC(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(t.Context(), nil, secret, true)

	traceID := "sg_tr_abc123"
	toolUseID := "tu_001"
	decision := "yellow"
	h.RecordTrace(TraceInfo{Decision: decision, ToolUseID: toolUseID, TraceID: traceID})

	token := GenerateToken(secret, traceID, toolUseID, decision)
	body := FeedbackRequest{
		StargateTrID:  traceID,
		ToolUseID:     toolUseID,
		Outcome:       "executed",
		FeedbackToken: token,
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.HandleFeedback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "recorded" {
		t.Errorf("status = %q, want recorded", resp["status"])
	}
}

func TestHandleFeedbackInvalidHMAC(t *testing.T) {
	secret, _ := GenerateSecret()
	h := NewHandler(t.Context(), nil, secret, true)

	traceID := "sg_tr_abc123"
	toolUseID := "tu_001"
	h.RecordTrace(TraceInfo{Decision: "yellow", ToolUseID: toolUseID, TraceID: traceID})

	body := FeedbackRequest{
		StargateTrID:  traceID,
		ToolUseID:     toolUseID,
		Outcome:       "executed",
		FeedbackToken: "badtoken",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.HandleFeedback(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid feedback token" {
		t.Errorf("error = %q, want 'invalid feedback token'", resp["error"])
	}
}

func TestHandleFeedbackExpiredTrace(t *testing.T) {
	secret, _ := GenerateSecret()
	h := NewHandler(t.Context(), nil, secret, true)

	// Don't record a trace — it should be "expired/not found".
	body := FeedbackRequest{
		StargateTrID:  "sg_tr_unknown",
		ToolUseID:     "tu_001",
		Outcome:       "executed",
		FeedbackToken: "sometoken",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.HandleFeedback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "trace_expired" {
		t.Errorf("status = %q, want trace_expired", resp["status"])
	}
}

func TestHandleFeedbackMissingFields(t *testing.T) {
	secret, _ := GenerateSecret()
	h := NewHandler(t.Context(), nil, secret, true)

	tests := []struct {
		name string
		body FeedbackRequest
	}{
		{"missing trace_id", FeedbackRequest{ToolUseID: "tu", Outcome: "executed", FeedbackToken: "tok"}},
		{"missing tool_use_id", FeedbackRequest{StargateTrID: "sg_tr_x", Outcome: "executed", FeedbackToken: "tok"}},
		{"missing outcome", FeedbackRequest{StargateTrID: "sg_tr_x", ToolUseID: "tu", FeedbackToken: "tok"}},
		{"missing token", FeedbackRequest{StargateTrID: "sg_tr_x", ToolUseID: "tu", Outcome: "executed"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
			w := httptest.NewRecorder()
			h.HandleFeedback(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}

func TestHandleFeedbackIdempotent(t *testing.T) {
	secret, _ := GenerateSecret()
	h := NewHandler(t.Context(), nil, secret, true)

	traceID := "sg_tr_idempotent"
	toolUseID := "tu_001"
	decision := "yellow"
	h.RecordTrace(TraceInfo{Decision: decision, ToolUseID: toolUseID, TraceID: traceID})

	token := GenerateToken(secret, traceID, toolUseID, decision)
	body := FeedbackRequest{
		StargateTrID:  traceID,
		ToolUseID:     toolUseID,
		Outcome:       "executed",
		FeedbackToken: token,
	}
	b, _ := json.Marshal(body)

	// First call.
	req1 := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
	w1 := httptest.NewRecorder()
	h.HandleFeedback(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200", w1.Code)
	}

	// Second call (idempotent — same trace still in TTL map).
	req2 := httptest.NewRequest("POST", "/feedback", bytes.NewReader(b))
	w2 := httptest.NewRecorder()
	h.HandleFeedback(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second call: status = %d, want 200", w2.Code)
	}
	var resp map[string]string
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["status"] != "recorded" {
		t.Errorf("status = %q, want recorded", resp["status"])
	}
}
