package llm

import (
	"context"
	"errors"

	"golang.org/x/time/rate"
)

// ErrRateLimited is returned by the rate-limited provider when the per-minute
// call budget is exhausted. Callers should map this to YELLOW (ask user)
// without performing an LLM review.
var ErrRateLimited = errors.New("llm: rate limit exceeded")

// rateLimitedProvider wraps a ReviewerProvider and enforces a maximum
// calls-per-minute limit using a token bucket.
type rateLimitedProvider struct {
	inner   ReviewerProvider
	limiter *rate.Limiter
}

// NewRateLimitedProvider returns a ReviewerProvider that allows at most
// maxCallsPerMinute calls per minute to the underlying provider.
//
// A burst allowance of 5 permits short bursts while maintaining the
// per-minute average over time.
//
// If maxCallsPerMinute <= 0, rate limiting is disabled and all calls pass
// through to the underlying provider unchanged.
func NewRateLimitedProvider(provider ReviewerProvider, maxCallsPerMinute int) ReviewerProvider {
	if provider == nil {
		return nil
	}
	if maxCallsPerMinute <= 0 {
		return provider
	}
	r := rate.Limit(float64(maxCallsPerMinute) / 60.0)
	return &rateLimitedProvider{
		inner:   provider,
		limiter: rate.NewLimiter(r, 5),
	}
}

// Review implements ReviewerProvider. It returns ErrRateLimited immediately
// (without blocking) if the per-minute budget is exhausted; otherwise it
// delegates to the underlying provider.
func (p *rateLimitedProvider) Review(ctx context.Context, req ReviewRequest) (ReviewResponse, error) {
	if err := ctx.Err(); err != nil {
		return ReviewResponse{}, err
	}
	if !p.limiter.Allow() {
		return ReviewResponse{}, ErrRateLimited
	}
	return p.inner.Review(ctx, req)
}
