package classifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/limbic-systems/stargate/internal/ttlmap"
)

// CachedDecision stores the final outcome for a classified command.
type CachedDecision struct {
	Decision string // final LLM verdict: "allow", "deny", or empty on error
	Action   string // final outcome: "allow", "block", "review"
}

// CommandCache wraps a TTLMap for exact-command deduplication.
type CommandCache struct {
	m   *ttlmap.TTLMap[string, CachedDecision]
	ttl time.Duration
}

// NewCommandCache creates a cache. If ttl <= 0 or maxEntries <= 0, returns
// a no-op cache that never hits.
func NewCommandCache(ctx context.Context, ttl time.Duration, maxEntries int) *CommandCache {
	if ttl <= 0 || maxEntries <= 0 {
		return &CommandCache{}
	}
	m := ttlmap.New[string, CachedDecision](ctx, ttlmap.Options{
		SweepInterval: max(ttl/10, 5*time.Second),
		MaxEntries:    maxEntries,
	})
	return &CommandCache{m: m, ttl: ttl}
}

// cacheKey returns SHA-256(rawCommand + "\x00" + cwd) as a hex string.
// The null-byte separator prevents domain collision between command and cwd.
func cacheKey(rawCommand, cwd string) string {
	h := sha256.New()
	h.Write([]byte(rawCommand))
	h.Write([]byte{0x00})
	h.Write([]byte(cwd))
	return hex.EncodeToString(h.Sum(nil))
}

// Lookup checks if the exact command+CWD has a cached decision.
// Returns false on cache miss or if the cache is disabled.
func (cc *CommandCache) Lookup(rawCommand, cwd string) (CachedDecision, bool) {
	if cc.m == nil {
		return CachedDecision{}, false
	}
	return cc.m.Get(cacheKey(rawCommand, cwd))
}

// Store caches a decision for the exact command+CWD.
// No-op if the cache is disabled.
func (cc *CommandCache) Store(rawCommand, cwd, decision, action string) {
	if cc.m == nil {
		return
	}
	cc.m.Set(cacheKey(rawCommand, cwd), CachedDecision{Decision: decision, Action: action}, cc.ttl)
}

// Clear empties the cache (called on config reload / SIGHUP).
func (cc *CommandCache) Clear() {
	if cc.m == nil {
		return
	}
	cc.m.Clear()
}
