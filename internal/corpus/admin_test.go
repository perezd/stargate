package corpus

import (
	"testing"
	"time"
)

// writeRecentEntry inserts an entry directly via ImportEntry (bypasses rate
// limiting) with a unique signature derived from the given suffix.
func writeRecentEntry(t *testing.T, c *Corpus, suffix, decision string) {
	t.Helper()
	sig := `[{"name":"cmd` + suffix + `","subcommand":"","flags":[],"context":"top_level"}]`
	e := PrecedentEntry{
		Signature:    sig,
		CommandNames: []string{"cmd" + suffix},
		Flags:        []string{},
		Decision:     decision,
		RawCommand:   "cmd" + suffix,
		Reasoning:    "reasoning for " + suffix,
	}
	if err := c.ImportEntry(e); err != nil {
		t.Fatalf("ImportEntry(%q, %q): %v", suffix, decision, err)
	}
}

func TestRecent_Basic(t *testing.T) {
	c := openTestCorpus(t)

	writeRecentEntry(t, c, "1", "allow")
	writeRecentEntry(t, c, "2", "deny")
	writeRecentEntry(t, c, "3", "allow")

	entries, err := c.Recent(RecentFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify ordered by created_at DESC (most recent first).
	// IDs are auto-increment, so higher ID = later insertion = more recent.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].CreatedAt.Before(entries[i].CreatedAt) {
			t.Errorf("entries not ordered DESC: entry[%d].CreatedAt=%v is before entry[%d].CreatedAt=%v",
				i-1, entries[i-1].CreatedAt, i, entries[i].CreatedAt)
		}
	}
}

func TestRecent_FilterDecision(t *testing.T) {
	c := openTestCorpus(t)

	writeRecentEntry(t, c, "a", "allow")
	writeRecentEntry(t, c, "b", "deny")
	writeRecentEntry(t, c, "c", "allow")
	writeRecentEntry(t, c, "d", "deny")

	entries, err := c.Recent(RecentFilter{Limit: 10, Decision: "deny"})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 deny entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Decision != "deny" {
			t.Errorf("expected decision=deny, got %q", e.Decision)
		}
	}
}

func TestRecent_Limit(t *testing.T) {
	c := openTestCorpus(t)

	for i := 0; i < 5; i++ {
		writeRecentEntry(t, c, string(rune('A'+i)), "allow")
	}

	entries, err := c.Recent(RecentFilter{Limit: 2})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (limit=2), got %d", len(entries))
	}
}

func TestRecent_Empty(t *testing.T) {
	c := openTestCorpus(t)

	entries, err := c.Recent(RecentFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Recent on empty corpus: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries on empty corpus, got %d", len(entries))
	}
}

func TestRecent_DefaultLimit(t *testing.T) {
	c := openTestCorpus(t)

	// Insert 25 entries — more than the default limit of 20.
	for i := 0; i < 25; i++ {
		writeRecentEntry(t, c, string(rune('A'+i%26))+string(rune('a'+i%26)), "allow")
	}

	// Limit=0 should fall back to default of 20.
	entries, err := c.Recent(RecentFilter{Limit: 0})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 20 {
		t.Fatalf("expected 20 entries (default limit), got %d", len(entries))
	}
}

func TestRecent_SinceFilter(t *testing.T) {
	c := openTestCorpus(t)

	// Insert an old entry directly with a past timestamp.
	past := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	_, err := c.db.Exec(`
		INSERT INTO precedents (signature, signature_hash, command_names, flags, decision, raw_command, created_at)
		VALUES ('oldsig', 'oldhash', '["old"]', '[]', 'allow', 'old cmd', ?)`, past)
	if err != nil {
		t.Fatalf("direct insert old entry: %v", err)
	}

	// Insert a fresh entry via ImportEntry.
	writeRecentEntry(t, c, "fresh", "allow")

	// Since=1h — the 48h-old entry should be excluded.
	entries, err := c.Recent(RecentFilter{Limit: 10, Since: time.Hour})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after Since filter, got %d", len(entries))
	}
	if entries[0].RawCommand != "cmdfresh" {
		t.Errorf("expected cmdfresh, got %q", entries[0].RawCommand)
	}
}
