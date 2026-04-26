package server

import (
	"context"
	"testing"
	"time"
)

func TestApplyTimeout_SetsDeadline(t *testing.T) {
	ctx, cancel := applyTimeout(context.Background(), "10s")
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context to have a deadline")
	}
	if time.Until(deadline) <= 0 {
		t.Error("deadline should be in the future")
	}
	if time.Until(deadline) > 11*time.Second {
		t.Errorf("deadline too far out: %v", time.Until(deadline))
	}
}

func TestApplyTimeout_EmptyString(t *testing.T) {
	ctx, cancel := applyTimeout(context.Background(), "")
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("empty timeout should not set a deadline")
	}
}

func TestApplyTimeout_InvalidDuration(t *testing.T) {
	ctx, cancel := applyTimeout(context.Background(), "not-a-duration")
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("invalid duration should not set a deadline")
	}
}

func TestApplyTimeout_ZeroDuration(t *testing.T) {
	ctx, cancel := applyTimeout(context.Background(), "0s")
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("zero duration should not set a deadline")
	}
}

func TestApplyTimeout_NegativeDuration(t *testing.T) {
	ctx, cancel := applyTimeout(context.Background(), "-5s")
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("negative duration should not set a deadline")
	}
}
