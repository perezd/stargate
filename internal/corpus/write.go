package corpus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/limbic-systems/stargate/internal/ttlmap"
)

// ErrRateLimited is returned by Write when either the per-signature or the
// global write rate limit is exceeded.
var ErrRateLimited = errors.New("corpus: write rate limited")

// PrecedentEntry represents a corpus entry for writing or reading.
type PrecedentEntry struct {
	ID            int64      // set on read; ignored on write (autoincrement)
	Signature     string
	SignatureHash string
	RawCommand    string
	CommandNames  []string   // stored as JSON array
	Flags         []string   // stored as JSON array
	ASTSummary    string
	CWD           string
	Decision      string     // "allow", "deny", or "user_approved"
	Reasoning     string
	RiskFactors   []string   // stored as JSON array
	MatchedRule   string
	ScopesInPlay  []string   // stored as JSON array
	TraceID       string
	SessionID     string
	Agent         string
	CreatedAt     time.Time  // set by DB default, populated on read
	LastHitAt     *time.Time
	HitCount      int
	Similarity    float64    // populated by lookup, not stored
}

// initRateLimiters sets up the per-signature and global TTLMaps on the Corpus.
// Called from Open after the Corpus struct is created.
func (c *Corpus) initRateLimiters(ctx context.Context) {
	// Per-signature limiter: track one write per signature_hash per hour.
	c.sigRateLimit = ttlmap.New[string, struct{}](ctx, ttlmap.Options{
		SweepInterval: 2 * time.Minute,
	})

	// Global limiter: track writes per minute-resolution bucket.
	c.globalRateLimit = ttlmap.New[string, int](ctx, ttlmap.Options{
		SweepInterval: 30 * time.Second,
	})
}

// Write inserts a precedent entry, subject to rate limiting.
// Returns ErrRateLimited if the per-signature or global rate limit is exceeded.
func (c *Corpus) Write(entry PrecedentEntry) error {
	// Validate required fields to prevent rate-limiter collapse (empty
	// SignatureHash would key all writes to "") and invalid corpus data.
	if entry.SignatureHash == "" || entry.Signature == "" {
		return fmt.Errorf("corpus: write requires non-empty signature and signature_hash")
	}
	if entry.Decision == "" {
		return fmt.Errorf("corpus: write requires non-empty decision")
	}

	// Serialize rate-limit decisions: Get→Set for both the per-signature and
	// global limits must be atomic so concurrent callers cannot both pass the
	// check before either sets the limit entry.
	c.rateMu.Lock()
	// Check both rate limits before committing either, so a rejection on one
	// doesn't consume the other's budget.

	// Global rate limit: max_writes_per_minute from config.
	var globalBucket string
	var globalCount int
	if c.cfg.MaxWritesPerMinute > 0 {
		globalBucket = globalBucketKey()
		globalCount, _ = c.globalRateLimit.Get(globalBucket)
		if globalCount >= c.cfg.MaxWritesPerMinute {
			c.rateMu.Unlock()
			return ErrRateLimited
		}
	}

	// Per-signature rate limit: 1 write per signature_hash+decision per hour.
	// Keyed on hash+decision so that an LLM "allow" write doesn't block a
	// subsequent "user_approved" write for the same structural signature.
	sigKey := entry.SignatureHash + ":" + entry.Decision
	if _, exists := c.sigRateLimit.Get(sigKey); exists {
		c.rateMu.Unlock()
		return ErrRateLimited
	}

	// Both checks passed — commit both entries atomically.
	if c.cfg.MaxWritesPerMinute > 0 {
		c.globalRateLimit.Set(globalBucket, globalCount+1, 61*time.Second)
	}
	c.sigRateLimit.Set(sigKey, struct{}{}, time.Hour)
	c.rateMu.Unlock()

	// JSON-encode []string fields.
	commandNamesJSON, err := marshalStringSlice(entry.CommandNames)
	if err != nil {
		return fmt.Errorf("corpus: marshal command_names: %w", err)
	}
	flagsJSON, err := marshalStringSlice(entry.Flags)
	if err != nil {
		return fmt.Errorf("corpus: marshal flags: %w", err)
	}
	riskFactorsJSON, err := marshalStringSlice(entry.RiskFactors)
	if err != nil {
		return fmt.Errorf("corpus: marshal risk_factors: %w", err)
	}
	scopesInPlayJSON, err := marshalStringSlice(entry.ScopesInPlay)
	if err != nil {
		return fmt.Errorf("corpus: marshal scopes_in_play: %w", err)
	}

	_, err = c.db.Exec(`
		INSERT INTO precedents (
			signature, signature_hash, raw_command, command_names, flags,
			ast_summary, cwd, decision, reasoning, risk_factors,
			matched_rule, scopes_in_play, stargate_trace_id, session_id, agent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Signature,
		entry.SignatureHash,
		toNullString(entry.RawCommand),
		commandNamesJSON,
		flagsJSON,
		toNullString(entry.ASTSummary),
		toNullString(entry.CWD),
		entry.Decision,
		toNullString(entry.Reasoning),
		toNullString(riskFactorsJSON),
		toNullString(entry.MatchedRule),
		toNullString(scopesInPlayJSON),
		toNullString(entry.TraceID),
		toNullString(entry.SessionID),
		toNullString(entry.Agent),
	)
	if err != nil {
		return fmt.Errorf("corpus: insert precedent: %w", err)
	}

	return nil
}

// globalBucketKey returns a string key for the current minute bucket.
func globalBucketKey() string {
	return time.Now().UTC().Format("2006-01-02T15:04")
}

// marshalStringSlice encodes a []string as a JSON array. A nil or empty slice
// is encoded as "[]" to keep the column well-formed.
func marshalStringSlice(s []string) (string, error) {
	if s == nil {
		s = []string{}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// toNullString returns a sql.NullString that is valid (non-NULL) only when s is
// non-empty, so SQLite stores NULL rather than an empty string for optional
// text columns.
func toNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
