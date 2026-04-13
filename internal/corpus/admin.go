package corpus

import (
	"database/sql"
	"fmt"
	"time"
)

// Stats holds aggregate statistics about the corpus.
type Stats struct {
	TotalEntries  int
	ByDecision    map[string]int
	OldestEntry   time.Time
	NewestEntry   time.Time
	HasEntries    bool
}

// Stats returns aggregate statistics about the corpus.
func (c *Corpus) Stats() (Stats, error) {
	var s Stats
	s.ByDecision = make(map[string]int)

	// Total count.
	if err := c.db.QueryRow("SELECT COUNT(*) FROM precedents").Scan(&s.TotalEntries); err != nil {
		return s, fmt.Errorf("corpus: stats total: %w", err)
	}

	// By decision.
	rows, err := c.db.Query("SELECT decision, COUNT(*) FROM precedents GROUP BY decision")
	if err != nil {
		return s, fmt.Errorf("corpus: stats by decision: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var decision string
		var count int
		if err := rows.Scan(&decision, &count); err != nil {
			return s, fmt.Errorf("corpus: stats scan decision: %w", err)
		}
		s.ByDecision[decision] = count
	}
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("corpus: stats rows: %w", err)
	}

	// Oldest/newest.
	if s.TotalEntries > 0 {
		s.HasEntries = true
		var oldest, newest string
		if err := c.db.QueryRow("SELECT MIN(created_at), MAX(created_at) FROM precedents").Scan(&oldest, &newest); err != nil {
			return s, fmt.Errorf("corpus: stats dates: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, oldest); err == nil {
			s.OldestEntry = t
		}
		if t, err := time.Parse(time.RFC3339, newest); err == nil {
			s.NewestEntry = t
		}
	}

	return s, nil
}

// GetByID retrieves a single precedent entry by its ID.
// Returns sql.ErrNoRows if the ID does not exist.
func (c *Corpus) GetByID(id int64) (PrecedentEntry, error) {
	q := `
		SELECT id, signature, signature_hash, raw_command, command_names, flags,
		       ast_summary, cwd, decision, reasoning, risk_factors, matched_rule,
		       scopes_in_play, stargate_trace_id, created_at, last_hit_at, hit_count,
		       session_id, agent
		FROM precedents WHERE id = ?`
	rows, err := c.db.Query(q, id)
	if err != nil {
		return PrecedentEntry{}, fmt.Errorf("corpus: get by id: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return PrecedentEntry{}, fmt.Errorf("corpus: get by id rows: %w", err)
		}
		return PrecedentEntry{}, sql.ErrNoRows
	}

	e, err := scanEntry(rows)
	if err != nil {
		return PrecedentEntry{}, fmt.Errorf("corpus: get by id scan: %w", err)
	}
	return e.PrecedentEntry, nil
}

// DeleteByID deletes a single precedent entry by its ID.
// Returns the number of rows deleted (0 if the ID did not exist).
func (c *Corpus) DeleteByID(id int64) (int64, error) {
	res, err := c.db.Exec("DELETE FROM precedents WHERE id = ?", id)
	if err != nil {
		return 0, fmt.Errorf("corpus: delete by id: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("corpus: delete by id rows affected: %w", err)
	}
	return n, nil
}

// DeleteAll deletes all entries from the corpus.
// Returns the number of rows deleted.
func (c *Corpus) DeleteAll() (int64, error) {
	res, err := c.db.Exec("DELETE FROM precedents")
	if err != nil {
		return 0, fmt.Errorf("corpus: delete all: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("corpus: delete all rows affected: %w", err)
	}
	return n, nil
}

// ExportAll returns all precedent entries in the corpus, ordered by ID.
func (c *Corpus) ExportAll() ([]PrecedentEntry, error) {
	q := `
		SELECT id, signature, signature_hash, raw_command, command_names, flags,
		       ast_summary, cwd, decision, reasoning, risk_factors, matched_rule,
		       scopes_in_play, stargate_trace_id, created_at, last_hit_at, hit_count,
		       session_id, agent
		FROM precedents ORDER BY id ASC`
	rows, err := c.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("corpus: export all: %w", err)
	}
	defer rows.Close()

	var entries []PrecedentEntry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("corpus: export all scan: %w", err)
		}
		entries = append(entries, e.PrecedentEntry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("corpus: export all rows: %w", err)
	}
	return entries, nil
}

// ImportEntry inserts a single PrecedentEntry, bypassing rate limiting.
// This is intended for admin import operations only.
//
// Note: import is not a lossless round-trip. CreatedAt, LastHitAt, and HitCount
// are not preserved — the database sets created_at to the current time and
// hit_count defaults to 0. Imported entries are intentionally treated as fresh.
func (c *Corpus) ImportEntry(entry PrecedentEntry) error {
	commandNamesJSON, err := marshalStringSlice(entry.CommandNames)
	if err != nil {
		return fmt.Errorf("corpus: import marshal command_names: %w", err)
	}
	flagsJSON, err := marshalStringSlice(entry.Flags)
	if err != nil {
		return fmt.Errorf("corpus: import marshal flags: %w", err)
	}
	riskFactorsJSON, err := marshalStringSlice(entry.RiskFactors)
	if err != nil {
		return fmt.Errorf("corpus: import marshal risk_factors: %w", err)
	}
	scopesInPlayJSON, err := marshalStringSlice(entry.ScopesInPlay)
	if err != nil {
		return fmt.Errorf("corpus: import marshal scopes_in_play: %w", err)
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
		return fmt.Errorf("corpus: import insert: %w", err)
	}
	return nil
}
