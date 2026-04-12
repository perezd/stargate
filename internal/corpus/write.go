package corpus

import (
	"context"
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
	// Per-signature rate limit: 1 write per signature_hash per hour.
	// Set the entry BEFORE the DB insert so concurrent callers see it and fail
	// closed rather than racing past this check. A failed insert "wastes" one
	// rate-limit slot — acceptable because it blocks rather than allows.
	if _, exists := c.sigRateLimit.Get(entry.SignatureHash); exists {
		return ErrRateLimited
	}
	c.sigRateLimit.Set(entry.SignatureHash, struct{}{}, time.Hour)

	// Global rate limit: max_writes_per_minute from config.
	if c.cfg.MaxWritesPerMinute > 0 {
		bucketKey := globalBucketKey()
		count, _ := c.globalRateLimit.Get(bucketKey)
		if count >= c.cfg.MaxWritesPerMinute {
			return ErrRateLimited
		}
		// Increment the counter (TTL = remainder of this minute + 1s buffer).
		c.globalRateLimit.Set(bucketKey, count+1, 61*time.Second)
	}

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
		nullableString(entry.RawCommand),
		commandNamesJSON,
		flagsJSON,
		nullableString(entry.ASTSummary),
		nullableString(entry.CWD),
		entry.Decision,
		nullableString(entry.Reasoning),
		nullableString(riskFactorsJSON),
		nullableString(entry.MatchedRule),
		nullableString(scopesInPlayJSON),
		nullableString(entry.TraceID),
		nullableString(entry.SessionID),
		nullableString(entry.Agent),
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

// nullableString returns nil for empty strings so SQLite stores NULL rather
// than an empty string for optional text columns.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
