// Package classifier orchestrates the stargate classification pipeline:
// parse → rules → (corpus, LLM in future milestones).
package classifier

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/perezd/stargate/internal/config"
	"github.com/perezd/stargate/internal/parser"
	"github.com/perezd/stargate/internal/rules"
)

// Classifier orchestrates the parse → rule-engine pipeline.
type Classifier struct {
	engine       *rules.Engine
	walkerCfg    *parser.WalkerConfig
	dialect      string
	maxCmdLen    int
	maxASTDepth  int
	unresolvable string
}

// ClassifyRequest is the input to the classifier.
type ClassifyRequest struct {
	Command     string         `json:"command"`
	CWD         string         `json:"cwd,omitempty"`
	Description string         `json:"description,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

// ClassifyResponse is the output of the classifier.
// All fields match the spec §6.1 response schema. Fields not yet implemented
// (FeedbackToken, Corpus) are nil in M2 for forward compatibility.
type ClassifyResponse struct {
	Decision      string             `json:"decision"`
	Action        string             `json:"action"`
	Reason        string             `json:"reason"`
	Guidance      string             `json:"guidance,omitempty"`
	StargateTrID  string             `json:"stargate_trace_id"`
	FeedbackToken *string            `json:"feedback_token"`
	Rule          *rules.MatchedRule `json:"rule"`
	LLMReview     *LLMReviewResult   `json:"llm_review"`
	Timing        *Timing            `json:"timing"`
	AST           *ASTSummary        `json:"ast"`
	Context       map[string]any     `json:"context"`
	Corpus        *CorpusSummary     `json:"corpus"`
	Version       string             `json:"version"`
}

// LLMReviewResult holds the result of an LLM review (populated in M4).
// Shape matches the documented spec §6.1 to avoid breaking API changes later.
type LLMReviewResult struct {
	Performed      bool     `json:"performed"`
	Decision       string   `json:"decision"`
	Reasoning      string   `json:"reasoning"`
	RiskFactors    []string `json:"risk_factors"`
	FilesRequested []string `json:"files_requested"`
	FilesInspected []string `json:"files_inspected"`
	FilesDenied    []string `json:"files_denied"`
	Rounds         int      `json:"rounds"`
	DurationMs     float64  `json:"duration_ms"`
}

// CorpusSummary holds precedent corpus interaction details (populated in M5).
// Shape matches spec §6.1.
type CorpusSummary struct {
	PrecedentsFound int  `json:"precedents_found"`
	EntryWritten    bool `json:"entry_written"`
}

// Timing holds per-phase duration measurements.
type Timing struct {
	ParseUs int64   `json:"parse_us"`
	RulesUs int64   `json:"rules_us"`
	LLMMs   float64 `json:"llm_ms"`
	TotalMs float64 `json:"total_ms"`
}

// ASTSummary summarises relevant properties of the parsed command AST.
type ASTSummary struct {
	CommandsFound    int              `json:"commands_found"`
	MaxDepth         int              `json:"max_depth"`
	HasPipes         bool             `json:"has_pipes"`
	HasSubshells     bool             `json:"has_subshells"`
	HasSubstitutions bool             `json:"has_substitutions"`
	HasRedirections  bool             `json:"has_redirections"`
	Commands         []CommandSummary `json:"commands"`
}

// CommandSummary is a compact representation of a single CommandInfo for the response.
type CommandSummary struct {
	Name       string   `json:"name"`
	Context    string   `json:"context"`
	Subcommand string   `json:"subcommand,omitempty"`
	Flags      []string `json:"flags,omitempty"`
	Args       []string `json:"args,omitempty"`
}

const version = "m2"

// New creates a Classifier from the given config.
// Returns an error if the rule engine cannot be compiled.
func New(cfg *config.Config) (*Classifier, error) {
	eng, err := rules.NewEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("classifier: build engine: %w", err)
	}

	wc := parser.NewWalkerConfig(cfg.Wrappers, cfg.Commands)

	return &Classifier{
		engine:       eng,
		walkerCfg:    wc,
		dialect:      cfg.Parser.Dialect,
		maxCmdLen:    cfg.Classifier.MaxCommandLength,
		maxASTDepth:  cfg.Classifier.MaxASTDepth,
		unresolvable: cfg.Classifier.UnresolvableExpansion,
	}, nil
}

// Classify runs the classification pipeline and returns a response.
// It never returns nil.
func (c *Classifier) Classify(req ClassifyRequest) *ClassifyResponse {
	start := time.Now()
	traceID := newTraceID()

	// Normalize command — owned by the classifier so all entry points
	// (HTTP, CLI, tests) behave consistently.
	req.Command = strings.TrimSpace(req.Command)

	// Base response — common fields populated once so no early-return path
	// can accidentally omit them (e.g., Context echo, trace ID, version).
	resp := &ClassifyResponse{
		StargateTrID: traceID,
		Context:      req.Context,
		Timing:       &Timing{},
		// AST is nil until parsing succeeds (spec: ast is null on parse failure).
		Version: version,
	}

	finalize := func() *ClassifyResponse {
		resp.Timing.TotalMs = float64(time.Since(start).Microseconds()) / 1000
		return resp
	}

	// 1. Command length guard.
	if c.maxCmdLen > 0 && len(req.Command) > c.maxCmdLen {
		resp.Decision = "red"
		resp.Action = "block"
		resp.Reason = fmt.Sprintf("command exceeds maximum length (%d > %d bytes)", len(req.Command), c.maxCmdLen)
		return finalize()
	}

	// 2. Parse phase.
	parseStart := time.Now()
	cmds, err := parser.ParseAndWalk(req.Command, c.dialect, c.walkerCfg)
	resp.Timing.ParseUs = time.Since(parseStart).Microseconds()

	if err != nil {
		resp.Decision = "red"
		resp.Action = "block"
		resp.Reason = err.Error()
		return finalize()
	}

	// 3. AST depth guard.
	resp.AST = buildASTSummary(cmds)
	if c.maxASTDepth > 0 && resp.AST.MaxDepth > c.maxASTDepth {
		resp.Decision = "red"
		resp.Action = "block"
		resp.Reason = fmt.Sprintf("AST depth %d exceeds limit %d", resp.AST.MaxDepth, c.maxASTDepth)
		return finalize()
	}

	// 4. Rule engine evaluation.
	// Unresolvable commands (Name == "") never match command/commands rules,
	// so they fail GREEN and fall to YELLOW/default. RED rules still fire for
	// other commands in the same input (e.g., "$(echo rm); rm -rf /").
	rulesStart := time.Now()
	result := c.engine.Evaluate(cmds, req.Command)
	resp.Timing.RulesUs = time.Since(rulesStart).Microseconds()

	// 5. Apply unresolvable_expansion policy.
	// If the engine returned a default decision (no rule matched) and any
	// command was unresolvable, override with the unresolvable_expansion
	// policy — but never downgrade a RED or explicit YELLOW result.
	if result.Rule == nil {
		for i := range cmds {
			if cmds[i].Name == "" {
				decision := c.unresolvable
				result.Decision = decision
				switch decision {
				case "red":
					result.Action = "block"
				case "green":
					result.Action = "allow"
				default:
					result.Action = "review"
				}
				result.Reason = "command name could not be statically resolved"
				break
			}
		}
	}

	resp.Decision = result.Decision
	resp.Action = result.Action
	resp.Reason = result.Reason
	resp.Rule = result.Rule
	return finalize()
}

// buildASTSummary derives an ASTSummary from the parsed CommandInfo slice.
func buildASTSummary(cmds []rules.CommandInfo) *ASTSummary {
	s := &ASTSummary{
		CommandsFound: len(cmds),
		Commands:      make([]CommandSummary, 0, len(cmds)),
	}
	for i := range cmds {
		cmd := &cmds[i]

		// Track max structural depth (1-based). Reflects subshell nesting and
		// pipeline position per spec examples (simple cmd = 1, 2-stage pipe = 2).
		cmdDepth := max(1+cmd.Context.SubshellDepth, cmd.Context.PipelinePosition)
		if cmdDepth > s.MaxDepth {
			s.MaxDepth = cmdDepth
		}

		// Boolean flags.
		if cmd.Context.PipelinePosition >= 1 {
			s.HasPipes = true
		}
		if cmd.Context.SubshellDepth > 0 {
			s.HasSubshells = true
		}
		if cmd.Context.InSubstitution {
			s.HasSubstitutions = true
		}
		if len(cmd.Redirects) > 0 {
			s.HasRedirections = true
		}

		s.Commands = append(s.Commands, CommandSummary{
			Name:       cmd.Name,
			Context:    contextString(cmd),
			Subcommand: cmd.Subcommand,
			Flags:      cmd.Flags,
			Args:       cmd.Args,
		})
	}
	return s
}

// contextString derives a human-readable context label from a CommandInfo,
// matching the spec's ast.commands[*].context enum.
func contextString(cmd *rules.CommandInfo) string {
	switch {
	case cmd.Context.InSubstitution:
		return "substitution"
	case cmd.Context.InCondition:
		return "condition"
	case cmd.Context.InFunction != "":
		return "function"
	case cmd.Context.SubshellDepth > 0:
		return "subshell"
	case cmd.Context.PipelinePosition == 1:
		return "pipeline_source"
	case cmd.Context.PipelinePosition >= 2:
		return "pipeline_sink"
	default:
		return "top_level"
	}
}


// newTraceID generates a random trace ID with the sg_tr_ prefix.
func newTraceID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// Fallback — deterministic 12 bytes from timestamp hash to preserve
		// the fixed sg_tr_ + 24-hex-char format.
		h := sha256.Sum256(fmt.Appendf(nil, "%d", time.Now().UnixNano()))
		copy(b, h[:12])
	}
	return "sg_tr_" + hex.EncodeToString(b)
}
