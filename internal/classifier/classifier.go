// Package classifier orchestrates the stargate classification pipeline:
// parse → rules → (corpus, LLM in future milestones).
package classifier

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
type ClassifyResponse struct {
	Decision     string            `json:"decision"`
	Action       string            `json:"action"`
	Reason       string            `json:"reason"`
	Guidance     string            `json:"guidance,omitempty"`
	StargateTrID string            `json:"stargate_trace_id"`
	Rule         *rules.MatchedRule `json:"rule"`
	LLMReview    *LLMReviewResult  `json:"llm_review"`
	Timing       *Timing           `json:"timing"`
	AST          *ASTSummary       `json:"ast"`
	Context      map[string]any    `json:"context,omitempty"`
	Version      string            `json:"version"`
}

// LLMReviewResult holds the result of an LLM review (populated in M4).
type LLMReviewResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Timing holds per-phase duration measurements.
type Timing struct {
	ParseUs int64 `json:"parse_us"`
	RulesUs int64 `json:"rules_us"`
	TotalMs int64 `json:"total_ms"`
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
	Name       string `json:"name"`
	Subcommand string `json:"subcommand,omitempty"`
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

	// 1. Command length guard.
	if c.maxCmdLen > 0 && len(req.Command) > c.maxCmdLen {
		elapsed := time.Since(start)
		return &ClassifyResponse{
			Decision:     "red",
			Action:       "block",
			Reason:       fmt.Sprintf("command exceeds maximum length (%d > %d bytes)", len(req.Command), c.maxCmdLen),
			StargateTrID: traceID,
			Timing: &Timing{
				TotalMs: elapsed.Milliseconds(),
			},
			AST:     &ASTSummary{},
			Version: version,
		}
	}

	// 2. Parse phase.
	parseStart := time.Now()
	cmds, err := parser.ParseAndWalk(req.Command, c.dialect, c.walkerCfg)
	parseUs := time.Since(parseStart).Microseconds()

	if err != nil {
		elapsed := time.Since(start)
		return &ClassifyResponse{
			Decision:     "red",
			Action:       "block",
			Reason:       fmt.Sprintf("parse error: %s", err.Error()),
			StargateTrID: traceID,
			Timing: &Timing{
				ParseUs: parseUs,
				TotalMs: elapsed.Milliseconds(),
			},
			AST:     &ASTSummary{},
			Version: version,
		}
	}

	// 3. AST depth guard.
	astSummary := buildASTSummary(cmds)
	if c.maxASTDepth > 0 && astSummary.MaxDepth > c.maxASTDepth {
		elapsed := time.Since(start)
		return &ClassifyResponse{
			Decision:     "red",
			Action:       "block",
			Reason:       fmt.Sprintf("AST depth %d exceeds limit %d", astSummary.MaxDepth, c.maxASTDepth),
			StargateTrID: traceID,
			Timing: &Timing{
				ParseUs: parseUs,
				TotalMs: elapsed.Milliseconds(),
			},
			AST:     astSummary,
			Version: version,
		}
	}

	// 4. Rule engine evaluation.
	// Unresolvable commands (Name == "") never match command/commands rules,
	// so they fail GREEN and fall to YELLOW/default. RED rules still fire for
	// other commands in the same input (e.g., "$(echo rm); rm -rf /").
	rulesStart := time.Now()
	result := c.engine.Evaluate(cmds, req.Command)
	rulesUs := time.Since(rulesStart).Microseconds()

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

	elapsed := time.Since(start)

	return &ClassifyResponse{
		Decision:     result.Decision,
		Action:       result.Action,
		Reason:       result.Reason,
		StargateTrID: traceID,
		Rule:         result.Rule,
		Timing: &Timing{
			ParseUs: parseUs,
			RulesUs: rulesUs,
			TotalMs: elapsed.Milliseconds(),
		},
		AST:     astSummary,
		Version: version,
	}
}

// buildASTSummary derives an ASTSummary from the parsed CommandInfo slice.
func buildASTSummary(cmds []rules.CommandInfo) *ASTSummary {
	s := &ASTSummary{
		CommandsFound: len(cmds),
		Commands:      make([]CommandSummary, 0, len(cmds)),
	}
	for i := range cmds {
		cmd := &cmds[i]

		// Track max subshell depth.
		if cmd.Context.SubshellDepth > s.MaxDepth {
			s.MaxDepth = cmd.Context.SubshellDepth
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
			Subcommand: cmd.Subcommand,
			Flags:      cmd.Flags,
			Args:       cmd.Args,
		})
	}
	return s
}


// newTraceID generates a random trace ID with the sg_tr_ prefix.
func newTraceID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// Fallback — deterministic 12 bytes from timestamp hash to preserve
		// the fixed sg_tr_ + 24-hex-char format.
		h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		copy(b, h[:12])
	}
	return "sg_tr_" + hex.EncodeToString(b)
}
