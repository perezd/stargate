package corpus

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LookupConfig holds parameters for similarity search.
type LookupConfig struct {
	MinSimilarity  float64
	MaxPrecedents  int
	MaxPerPolarity int
	MaxAge         time.Duration
}

// LookupSimilar finds precedents with overlapping command names, computes
// Jaccard similarity against the provided signature, and returns balanced
// results across positive (allow/user_approved) and negative (deny) polarities.
func (c *Corpus) LookupSimilar(cmdNames []string, signature string, cfg LookupConfig) ([]PrecedentEntry, error) {
	cutoff := time.Now().UTC().Add(-cfg.MaxAge).Format(time.RFC3339)

	// Build the IN clause placeholders for command name matching.
	if len(cmdNames) == 0 {
		return nil, nil
	}

	args := make([]interface{}, len(cmdNames)+1)
	for i, n := range cmdNames {
		args[i] = n
	}
	args[len(cmdNames)] = cutoff

	placeholders := strings.Repeat("?,", len(cmdNames))
	placeholders = placeholders[:len(placeholders)-1] // trim trailing comma

	// Query positive polarity (allow + user_approved).
	posQuery := fmt.Sprintf(`
		SELECT id, signature, signature_hash, raw_command, command_names, flags,
		       ast_summary, cwd, decision, reasoning, risk_factors, matched_rule,
		       scopes_in_play, stargate_trace_id, created_at, last_hit_at, hit_count,
		       session_id, agent
		FROM precedents
		WHERE EXISTS (
			SELECT 1 FROM json_each(command_names) WHERE value IN (%s)
		)
		  AND decision IN ('allow', 'user_approved')
		  AND created_at > ?
		ORDER BY created_at DESC
		LIMIT 100`, placeholders)

	posCandidates, err := c.queryEntries(posQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("corpus: lookup positive candidates: %w", err)
	}

	// Query negative polarity (deny).
	negQuery := fmt.Sprintf(`
		SELECT id, signature, signature_hash, raw_command, command_names, flags,
		       ast_summary, cwd, decision, reasoning, risk_factors, matched_rule,
		       scopes_in_play, stargate_trace_id, created_at, last_hit_at, hit_count,
		       session_id, agent
		FROM precedents
		WHERE EXISTS (
			SELECT 1 FROM json_each(command_names) WHERE value IN (%s)
		)
		  AND decision = 'deny'
		  AND created_at > ?
		ORDER BY created_at DESC
		LIMIT 100`, placeholders)

	negCandidates, err := c.queryEntries(negQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("corpus: lookup negative candidates: %w", err)
	}

	// Parse the query signature tuples for Jaccard computation.
	querySigSet := parseSigSet(signature)

	// Score and filter each polarity group independently.
	posSimilar := scoredFilter(posCandidates, querySigSet, cfg.MinSimilarity, cfg.MaxPerPolarity)
	negSimilar := scoredFilter(negCandidates, querySigSet, cfg.MinSimilarity, cfg.MaxPerPolarity)

	// Merge: interleave for balance, cap at MaxPrecedents.
	results := merge(posSimilar, negSimilar, cfg.MaxPrecedents)

	// Update hit stats for returned entries.
	if len(results) > 0 {
		ids := make([]int64, len(results))
		for i := range results {
			ids[i] = results[i].id
		}
		if err := c.updateHitStats(ids); err != nil {
			// Non-fatal: best effort update.
			_ = err
		}
	}

	// Strip internal id field from returned entries.
	out := make([]PrecedentEntry, len(results))
	for i, r := range results {
		out[i] = r.PrecedentEntry
	}
	return out, nil
}

// scoredEntry pairs a PrecedentEntry with its internal DB id (for hit updates).
type scoredEntry struct {
	PrecedentEntry
	id int64
}

// scoredFilter computes Jaccard similarity for each candidate, filters by
// MinSimilarity, and caps the result at maxCount.
func scoredFilter(candidates []scoredEntry, querySigSet map[string]struct{}, minSim float64, maxCount int) []scoredEntry {
	scored := make([]scoredEntry, 0, len(candidates))
	for _, c := range candidates {
		candSigSet := parseSigSet(c.Signature)
		sim := jaccard(querySigSet, candSigSet)
		if sim >= minSim {
			c.Similarity = sim
			scored = append(scored, c)
		}
	}
	if maxCount > 0 && len(scored) > maxCount {
		scored = scored[:maxCount]
	}
	return scored
}

// merge interleaves positive and negative results, capping total at maxTotal.
func merge(pos, neg []scoredEntry, maxTotal int) []scoredEntry {
	result := make([]scoredEntry, 0, len(pos)+len(neg))
	pi, ni := 0, 0
	for (pi < len(pos) || ni < len(neg)) && (maxTotal <= 0 || len(result) < maxTotal) {
		if pi < len(pos) {
			result = append(result, pos[pi])
			pi++
			if maxTotal > 0 && len(result) >= maxTotal {
				break
			}
		}
		if ni < len(neg) {
			result = append(result, neg[ni])
			ni++
		}
	}
	return result
}

// parseSigSet parses a JSON signature string into a set of tuple strings.
// Each element in the JSON array is re-serialized as a canonical string for
// set membership tests.
func parseSigSet(signature string) map[string]struct{} {
	var tuples []signatureTuple
	if err := json.Unmarshal([]byte(signature), &tuples); err != nil {
		return map[string]struct{}{}
	}
	set := make(map[string]struct{}, len(tuples))
	for _, t := range tuples {
		b, err := json.Marshal(t)
		if err != nil {
			continue
		}
		set[string(b)] = struct{}{}
	}
	return set
}

// jaccard computes |A ∩ B| / |A ∪ B| for two string sets.
// Returns 1.0 if both sets are empty (identical empty commands).
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	intersection := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// queryEntries executes q and scans each row into a scoredEntry.
func (c *Corpus) queryEntries(q string, args ...interface{}) ([]scoredEntry, error) {
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []scoredEntry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// scanEntry scans a row from the precedents SELECT into a scoredEntry.
func scanEntry(rows *sql.Rows) (scoredEntry, error) {
	var (
		e             scoredEntry
		rawCommand    sql.NullString
		astSummary    sql.NullString
		cwd           sql.NullString
		reasoning     sql.NullString
		riskFactors   sql.NullString
		matchedRule   sql.NullString
		scopesInPlay  sql.NullString
		traceID       sql.NullString
		createdAt     string
		lastHitAt     sql.NullString
		sessionID     sql.NullString
		agent         sql.NullString
		commandNames  string
		flags         string
	)

	err := rows.Scan(
		&e.id,
		&e.Signature,
		&e.SignatureHash,
		&rawCommand,
		&commandNames,
		&flags,
		&astSummary,
		&cwd,
		&e.Decision,
		&reasoning,
		&riskFactors,
		&matchedRule,
		&scopesInPlay,
		&traceID,
		&createdAt,
		&lastHitAt,
		&e.HitCount,
		&sessionID,
		&agent,
	)
	if err != nil {
		return e, err
	}

	e.RawCommand = rawCommand.String
	e.ASTSummary = astSummary.String
	e.CWD = cwd.String
	e.Reasoning = reasoning.String
	e.MatchedRule = matchedRule.String
	e.TraceID = traceID.String
	e.SessionID = sessionID.String
	e.Agent = agent.String

	// Parse created_at.
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		e.CreatedAt = t
	}

	// Parse last_hit_at.
	if lastHitAt.Valid && lastHitAt.String != "" {
		if t, err := time.Parse(time.RFC3339, lastHitAt.String); err == nil {
			e.LastHitAt = &t
		}
	}

	// Unmarshal JSON arrays.
	if err := json.Unmarshal([]byte(commandNames), &e.CommandNames); err != nil {
		e.CommandNames = nil
	}
	if err := json.Unmarshal([]byte(flags), &e.Flags); err != nil {
		e.Flags = nil
	}
	if riskFactors.Valid && riskFactors.String != "" {
		if err := json.Unmarshal([]byte(riskFactors.String), &e.RiskFactors); err != nil {
			e.RiskFactors = nil
		}
	}
	if scopesInPlay.Valid && scopesInPlay.String != "" {
		if err := json.Unmarshal([]byte(scopesInPlay.String), &e.ScopesInPlay); err != nil {
			e.ScopesInPlay = nil
		}
	}

	return e, nil
}

// updateHitStats increments hit_count and sets last_hit_at for all returned IDs.
func (c *Corpus) updateHitStats(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	now := time.Now().UTC().Format(time.RFC3339)
	allArgs := append([]interface{}{now}, args...)

	_, err := c.db.Exec(fmt.Sprintf(`
		UPDATE precedents
		SET hit_count = hit_count + 1,
		    last_hit_at = ?
		WHERE id IN (%s)`, placeholders),
		allArgs...,
	)
	return err
}
