package llm

import (
	"context"
	"errors"
	"testing"
)

// stubProvider is a ReviewerProvider that always succeeds and records how many
// times it was called.
type stubProvider struct {
	calls int
	resp  ReviewResponse
	err   error
}

func (s *stubProvider) Review(_ context.Context, _ ReviewRequest) (ReviewResponse, error) {
	s.calls++
	return s.resp, s.err
}

func TestRateLimitWithinBudget(t *testing.T) {
	stub := &stubProvider{resp: ReviewResponse{Decision: "allow"}}
	// 60 calls/min → 1 token/s, burst 5. First 5 calls should succeed immediately.
	p := NewRateLimitedProvider(stub, 60)

	for i := 0; i < 5; i++ {
		resp, err := p.Review(context.Background(), ReviewRequest{})
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if resp.Decision != "allow" {
			t.Fatalf("call %d: expected decision 'allow', got %q", i+1, resp.Decision)
		}
	}
	if stub.calls != 5 {
		t.Fatalf("expected 5 calls to inner provider, got %d", stub.calls)
	}
}

func TestRateLimitExceeded(t *testing.T) {
	stub := &stubProvider{resp: ReviewResponse{Decision: "allow"}}
	// 1 call/min → burst 5. Very low refill rate ensures no token arrives during
	// the test loop, making the 6th call reliably rejected.
	p := NewRateLimitedProvider(stub, 1)

	for i := 0; i < 5; i++ {
		if _, err := p.Review(context.Background(), ReviewRequest{}); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
	}

	_, err := p.Review(context.Background(), ReviewRequest{})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("6th call: expected ErrRateLimited, got %v", err)
	}
	// The inner provider must not have been called on the rejected attempt.
	if stub.calls != 5 {
		t.Fatalf("expected inner provider to be called 5 times, got %d", stub.calls)
	}
}

func TestRateLimitDisabledWhenZero(t *testing.T) {
	stub := &stubProvider{resp: ReviewResponse{Decision: "deny"}}
	p := NewRateLimitedProvider(stub, 0)

	// Far beyond any burst window — all calls must pass through.
	const n = 20
	for i := 0; i < n; i++ {
		resp, err := p.Review(context.Background(), ReviewRequest{})
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if resp.Decision != "deny" {
			t.Fatalf("call %d: expected decision 'deny', got %q", i+1, resp.Decision)
		}
	}
	if stub.calls != n {
		t.Fatalf("expected %d calls, got %d", n, stub.calls)
	}
}

func TestRateLimitDisabledWhenNegative(t *testing.T) {
	stub := &stubProvider{resp: ReviewResponse{Decision: "allow"}}
	p := NewRateLimitedProvider(stub, -1)

	const n = 20
	for i := 0; i < n; i++ {
		if _, err := p.Review(context.Background(), ReviewRequest{}); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
	}
	if stub.calls != n {
		t.Fatalf("expected %d calls, got %d", n, stub.calls)
	}
}

func TestErrRateLimitedIs(t *testing.T) {
	// Verify errors.Is works both directly and when wrapped.
	if !errors.Is(ErrRateLimited, ErrRateLimited) {
		t.Fatal("errors.Is(ErrRateLimited, ErrRateLimited) should be true")
	}
	wrapped := errors.Join(errors.New("outer"), ErrRateLimited)
	if !errors.Is(wrapped, ErrRateLimited) {
		t.Fatal("errors.Is on wrapped ErrRateLimited should be true")
	}
}

func TestRateLimitPassesThroughError(t *testing.T) {
	sentinel := errors.New("provider failure")
	stub := &stubProvider{err: sentinel}
	p := NewRateLimitedProvider(stub, 60)

	_, err := p.Review(context.Background(), ReviewRequest{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected provider error to be propagated, got %v", err)
	}
}
