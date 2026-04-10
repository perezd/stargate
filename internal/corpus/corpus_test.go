package corpus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/ttlmap"
)

func testCorpusConfig(path string) config.CorpusConfig {
	return config.CorpusConfig{
		Enabled:       true,
		Path:          path,
		MaxPrecedents: 5,
		MinSimilarity: 0.7,
		MaxAge:        "90d",
		MaxEntries:    10000,
		PruneInterval: "1h",
		MaxWritesPerMinute:      10,
		MaxReasoningLength:      1000,
		StoreDecisions:          "all",
		StoreReasoning:          true,
		StoreRawCommand:         true,
		StoreUserApprovals:      true,
		MaxPrecedentsPerDecision: 3,
	}
}

func TestOpenCreatesDBAndTables(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	// Verify the file exists.
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}

	// Verify the table exists by querying it.
	var count int
	err = c.DB().QueryRow("SELECT COUNT(*) FROM precedents").Scan(&count)
	if err != nil {
		t.Fatalf("query precedents table: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows, got %d", count)
	}
}

func TestOpenWALMode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	var mode string
	err = c.DB().QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestOpenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		t.Errorf("permissions = %o, want no group/other access", perm)
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "subdir", "nested", "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created in nested directory")
	}
}

func TestSchemaHasExpectedIndexes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	expectedIndexes := []string{
		"idx_precedents_hash",
		"idx_precedents_created",
		"idx_precedents_decision",
		"idx_precedents_trace",
		"idx_precedents_trace_decision",
	}

	for _, idx := range expectedIndexes {
		var name string
		err := c.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("index %q not found: %v", idx, err)
		}
	}
}

func TestCloseOrdering(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Insert a row to ensure WAL has data.
	_, err = c.DB().Exec(`
		INSERT INTO precedents (signature, signature_hash, command_names, flags, decision)
		VALUES ('[]', 'abc123', '["test"]', '[]', 'allow')
	`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Close should not hang or panic.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// DB should be closed — queries should fail.
	var count int
	err = c.DB().QueryRow("SELECT COUNT(*) FROM precedents").Scan(&count)
	if err == nil {
		t.Error("expected error querying closed database")
	}
}

func TestOpenEmptyPathReturnsError(t *testing.T) {
	cfg := testCorpusConfig("")
	_, err := Open(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSchemaHasExpectedColumns(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	expectedColumns := []string{
		"id", "signature", "signature_hash", "raw_command", "command_names",
		"flags", "ast_summary", "cwd", "decision", "reasoning", "risk_factors",
		"matched_rule", "scopes_in_play", "stargate_trace_id", "created_at",
		"last_hit_at", "hit_count", "session_id", "agent",
	}

	rows, err := c.DB().Query("PRAGMA table_info(precedents)")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		columns[name] = true
	}

	for _, col := range expectedColumns {
		if !columns[col] {
			t.Errorf("missing column: %s", col)
		}
	}
}

// ---- Write / Lookup tests ----

// sampleEntry returns a PrecedentEntry suitable for testing.
func sampleEntry(sig, hash, decision string) PrecedentEntry {
	return PrecedentEntry{
		Signature:     sig,
		SignatureHash: hash,
		RawCommand:    "git status",
		CommandNames:  []string{"git"},
		Flags:         []string{},
		Decision:      decision,
		Reasoning:     "test reasoning",
		RiskFactors:   []string{"r1"},
		ScopesInPlay:  []string{"scope1"},
		TraceID:       "trace-" + hash,
		SessionID:     "sess-1",
		Agent:         "test-agent",
	}
}

// openTestCorpus opens a corpus with a fresh temp DB.
func openTestCorpus(t *testing.T) *Corpus {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)
	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestWriteAndReadBack writes an entry and verifies it can be read by hash.
func TestWriteAndReadBack(t *testing.T) {
	c := openTestCorpus(t)

	sig := `[{"name":"git","subcommand":"status","flags":[],"context":"top_level"}]`
	hash := hashString(sig)
	e := sampleEntry(sig, hash, "allow")

	if err := c.Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var count int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM precedents WHERE signature_hash = ?", hash).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

// TestWriteDuplicateSignatureRateLimited verifies the per-signature rate limit
// blocks a second write for the same hash within an hour.
func TestWriteDuplicateSignatureRateLimited(t *testing.T) {
	c := openTestCorpus(t)

	sig := `[{"name":"curl","subcommand":"","flags":["-s"],"context":"top_level"}]`
	hash := hashString(sig)
	e := sampleEntry(sig, hash, "allow")

	if err := c.Write(e); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	err := c.Write(e)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

// TestWriteAfterRateLimitExpires verifies that a write succeeds once the TTL
// has elapsed by replacing the rate limiter with a very short TTL map.
func TestWriteAfterRateLimitExpires(t *testing.T) {
	c := openTestCorpus(t)

	// Replace the sig rate limiter with one that has a 50ms TTL sweep.
	c.sigRateLimit = ttlmap.New[string, struct{}](t.Context(), ttlmap.Options{
		SweepInterval: 10 * time.Millisecond,
	})

	sig := `[{"name":"ls","subcommand":"","flags":[],"context":"top_level"}]`
	hash := hashString(sig)
	e := sampleEntry(sig, hash, "allow")

	// First write — set a very short TTL so it expires quickly.
	if err := c.Write(e); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// Overwrite the rate limit entry with a 50ms TTL so it expires.
	c.sigRateLimit.Set(hash, struct{}{}, 50*time.Millisecond)

	time.Sleep(100 * time.Millisecond) // wait for expiry

	// Second write — should succeed now.
	if err := c.Write(e); err != nil {
		t.Fatalf("second Write after expiry: %v", err)
	}
}

// TestGlobalRateLimit verifies that exceeding max_writes_per_minute returns
// ErrRateLimited.
func TestGlobalRateLimit(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := testCorpusConfig(dbPath)
	cfg.MaxWritesPerMinute = 3

	c, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	// Write 3 entries with distinct hashes — all should succeed.
	for i := 0; i < 3; i++ {
		sig := `[{"name":"grep","subcommand":"","flags":[],"context":"top_level"}]`
		// Make each hash unique by appending the index.
		uniqueHash := hashString(sig) + string(rune('0'+i))
		e := sampleEntry(sig, uniqueHash, "allow")
		// Clear the per-sig limiter so it doesn't block us.
		c.sigRateLimit.Delete(uniqueHash)
		if err := c.Write(e); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// 4th write should hit the global limit.
	sig := `[{"name":"grep","subcommand":"","flags":[],"context":"top_level"}]`
	uniqueHash := hashString(sig) + "X"
	e := sampleEntry(sig, uniqueHash, "allow")
	err = c.Write(e)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited on global limit, got %v", err)
	}
}

// --- LookupSimilar tests ---

// writeSig is a helper that writes an entry with a given signature, bypassing
// the per-signature rate limit after the first write by resetting the TTL entry.
func writeSig(t *testing.T, c *Corpus, sig, decision string) {
	t.Helper()
	hash := hashString(sig)
	e := sampleEntry(sig, hash, decision)
	// Remove any existing rate limit entry so we can write multiple.
	c.sigRateLimit.Delete(hash)
	if err := c.Write(e); err != nil {
		t.Fatalf("writeSig(%q, %q): %v", decision, sig, err)
	}
}

func gitSig() string {
	return `[{"name":"git","subcommand":"status","flags":[],"context":"top_level"}]`
}

func curlSig() string {
	return `[{"name":"curl","subcommand":"","flags":["-s"],"context":"top_level"}]`
}

func defaultLookupConfig(c *Corpus) LookupConfig {
	return LookupConfig{
		MinSimilarity:  0.0,
		MaxPrecedents:  20,
		MaxPerPolarity: 10,
		MaxAge:         24 * time.Hour,
	}
}

// TestLookupSimilarFindsEntries writes 3 entries with the same signature and
// verifies LookupSimilar returns them.
func TestLookupSimilarFindsEntries(t *testing.T) {
	c := openTestCorpus(t)
	sig := gitSig()

	// Write 3 allow entries with the same signature (each with a distinct hash
	// to bypass per-sig rate limit).
	for i := 0; i < 3; i++ {
		hash := hashString(sig) + string(rune('a'+i))
		e := sampleEntry(sig, hash, "allow")
		if err := c.Write(e); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	results, err := c.LookupSimilar([]string{"git"}, sig, defaultLookupConfig(c))
	if err != nil {
		t.Fatalf("LookupSimilar: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

// TestLookupSimilarPolarityBalance writes 3 allow and 3 deny entries and
// verifies MaxPerPolarity=3 caps each side at 3.
func TestLookupSimilarPolarityBalance(t *testing.T) {
	c := openTestCorpus(t)
	sig := gitSig()

	for i := 0; i < 3; i++ {
		hash := hashString(sig) + "allow" + string(rune('a'+i))
		e := sampleEntry(sig, hash, "allow")
		if err := c.Write(e); err != nil {
			t.Fatalf("Write allow %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		hash := hashString(sig) + "deny" + string(rune('a'+i))
		e := sampleEntry(sig, hash, "deny")
		if err := c.Write(e); err != nil {
			t.Fatalf("Write deny %d: %v", i, err)
		}
	}

	cfg := LookupConfig{
		MinSimilarity:  0.0,
		MaxPrecedents:  20,
		MaxPerPolarity: 3,
		MaxAge:         24 * time.Hour,
	}
	results, err := c.LookupSimilar([]string{"git"}, sig, cfg)
	if err != nil {
		t.Fatalf("LookupSimilar: %v", err)
	}

	allowCount, denyCount := 0, 0
	for _, r := range results {
		switch r.Decision {
		case "allow", "user_approved":
			allowCount++
		case "deny":
			denyCount++
		}
	}
	if allowCount > 3 {
		t.Errorf("allow count %d exceeds MaxPerPolarity 3", allowCount)
	}
	if denyCount > 3 {
		t.Errorf("deny count %d exceeds MaxPerPolarity 3", denyCount)
	}
}

// TestLookupSimilarUserApprovedCountsAsPositive verifies that user_approved
// entries are returned alongside allow entries and not grouped with deny.
func TestLookupSimilarUserApprovedCountsAsPositive(t *testing.T) {
	c := openTestCorpus(t)
	sig := gitSig()

	// Write one user_approved entry.
	hash := hashString(sig) + "ua"
	e := sampleEntry(sig, hash, "user_approved")
	if err := c.Write(e); err != nil {
		t.Fatalf("Write user_approved: %v", err)
	}

	results, err := c.LookupSimilar([]string{"git"}, sig, defaultLookupConfig(c))
	if err != nil {
		t.Fatalf("LookupSimilar: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Decision != "user_approved" {
		t.Errorf("expected user_approved, got %q", results[0].Decision)
	}
}

// TestLookupSimilarJaccardFilter verifies that entries with dissimilar
// signatures are excluded when MinSimilarity is set above their Jaccard score.
func TestLookupSimilarJaccardFilter(t *testing.T) {
	c := openTestCorpus(t)

	// Write an entry with a "git" signature.
	gitSignature := gitSig()
	hash := hashString(gitSignature) + "j"
	e := sampleEntry(gitSignature, hash, "allow")
	if err := c.Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Lookup with a "curl" signature — Jaccard with git entry should be 0
	// since the tuples are completely different.
	curlSignature := curlSig()
	cfg := LookupConfig{
		MinSimilarity:  0.5, // require at least 50% similarity
		MaxPrecedents:  10,
		MaxPerPolarity: 10,
		MaxAge:         24 * time.Hour,
	}

	// Use both names so the SQL WHERE EXISTS matches (curl not in git entry).
	// Actually git entry has command_names=["git"], lookup by ["git"] to get a
	// candidate but the signature tuples differ — Jaccard should be 0.
	results, err := c.LookupSimilar([]string{"git"}, curlSignature, cfg)
	if err != nil {
		t.Fatalf("LookupSimilar: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results after Jaccard filter, got %d", len(results))
	}
}

// TestLookupSimilarMaxAgeFilter verifies that entries older than MaxAge are
// excluded from results.
func TestLookupSimilarMaxAgeFilter(t *testing.T) {
	c := openTestCorpus(t)
	sig := gitSig()

	// Insert an entry directly with an old created_at timestamp.
	past := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	_, err := c.db.Exec(`
		INSERT INTO precedents (signature, signature_hash, command_names, flags, decision, created_at)
		VALUES (?, ?, '["git"]', '[]', 'allow', ?)`,
		sig, hashString(sig)+"old", past,
	)
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}

	// MaxAge = 1 hour — the 48h-old entry should not appear.
	cfg := LookupConfig{
		MinSimilarity:  0.0,
		MaxPrecedents:  10,
		MaxPerPolarity: 10,
		MaxAge:         time.Hour,
	}
	results, err := c.LookupSimilar([]string{"git"}, sig, cfg)
	if err != nil {
		t.Fatalf("LookupSimilar: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d (old entries not filtered)", len(results))
	}
}

// TestWriteIdempotentUserApproved verifies that the UNIQUE constraint on
// (stargate_trace_id, decision) WHERE decision='user_approved' prevents
// duplicate user_approved entries for the same trace.
func TestWriteIdempotentUserApproved(t *testing.T) {
	c := openTestCorpus(t)
	sig := gitSig()
	hash := hashString(sig)

	// First user_approved entry.
	e := PrecedentEntry{
		Signature:     sig,
		SignatureHash: hash,
		CommandNames:  []string{"git"},
		Flags:         []string{},
		Decision:      "user_approved",
		TraceID:       "trace-abc",
	}
	if err := c.Write(e); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// Second insert with same trace_id and decision=user_approved should fail
	// due to UNIQUE constraint.
	e2 := e
	e2.SignatureHash = hash + "2" // different hash to pass per-sig rate limit
	_, err := c.db.Exec(`
		INSERT INTO precedents (signature, signature_hash, command_names, flags, decision, stargate_trace_id)
		VALUES (?, ?, '["git"]', '[]', 'user_approved', 'trace-abc')`,
		sig, hash+"2",
	)
	if err == nil {
		t.Error("expected UNIQUE constraint error for duplicate user_approved trace_id, got nil")
	}
}
