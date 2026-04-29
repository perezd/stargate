// Package classifier orchestrates the stargate classification pipeline:
// parse → rules → LLM review → (corpus in future milestones).
package classifier

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/corpus"
	"github.com/limbic-systems/stargate/internal/feedback"
	"github.com/limbic-systems/stargate/internal/llm"
	"github.com/limbic-systems/stargate/internal/parser"
	"github.com/limbic-systems/stargate/internal/rules"
	"github.com/limbic-systems/stargate/internal/scrub"
	"github.com/limbic-systems/stargate/internal/telemetry"
)

// Classifier orchestrates the parse → rule-engine → LLM review pipeline.
type Classifier struct {
	engine          *rules.Engine
	walkerCfg       *parser.WalkerConfig
	dialect         string
	maxCmdLen       int
	maxASTDepth     int
	unresolvable    string
	version         string // from config, included in every response
	llmProvider     llm.ReviewerProvider // nil = LLM review disabled
	llmProviderType string               // "anthropic_sdk", "oauth_subprocess", or ""
	scrubber        *scrub.Scrubber
	llmCfg          config.LLMConfig
	corpusCfg       config.CorpusConfig
	corpusMaxAge    time.Duration       // parsed once from corpusCfg.MaxAge
	scopes          map[string][]string // for prompt injection
	serverCWD       string              // for file retrieval path anchoring
	maxReasonLen    int                 // max reasoning chars in API response
	corpus          *corpus.Corpus      // nil = corpus disabled
	cmdCache        *CommandCache
	feedbackHandler *feedback.Handler
	hmacSecret      []byte
	cancel          context.CancelFunc  // cancels the classifier-lifecycle context
	tel             telemetry.Telemetry // defaults to NoOpTelemetry
}

// ClassifyRequest is the input to the classifier.
type ClassifyRequest struct {
	Command     string         `json:"command"`
	CWD         string         `json:"cwd,omitempty"`
	Description string         `json:"description,omitempty"`
	Context     map[string]any `json:"context,omitempty"`

	// DryRun is set by the /test handler to skip side effects (corpus writes,
	// cache reads/writes, feedback token generation). Tagged json:"-" so it
	// cannot be set via HTTP JSON input. Set only by the server-side handler.
	DryRun bool `json:"-"`

	// UseCache, when true in combination with DryRun, allows cache reads
	// during dry-run for debugging caching behavior. Cache writes are
	// always skipped during dry-run regardless of this flag. Tagged json:"-"
	// because the HTTP boundary is the TestRequest wrapper struct.
	UseCache bool `json:"-"`
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
	Debug         *DebugInfo         `json:"-"`
}

// LLMReviewResult holds the result of an LLM review (populated in M4).
// Shape matches the documented spec §6.1 to avoid breaking API changes later.
// Note: denied file paths are logged server-side (telemetry) only — they are
// intentionally omitted from the API response to avoid leaking which paths
// are on the deny list.
type LLMReviewResult struct {
	Performed      bool     `json:"performed"`
	Decision       string   `json:"decision"`
	Action         string   `json:"action,omitempty"` // populated on cache hit; empty for live LLM calls
	Reasoning      string   `json:"reasoning"`
	RiskFactors    []string `json:"risk_factors"`
	FilesRequested []string `json:"files_requested"`
	FilesInspected []string `json:"files_inspected"`
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

// New creates a Classifier from the given config.
// Returns an error if the rule engine or scrubber cannot be initialized.
func New(cfg *config.Config) (*Classifier, error) {
	eng, err := rules.NewEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("classifier: build engine: %w", err)
	}

	wc := parser.NewWalkerConfig(cfg.Wrappers, cfg.Commands)

	// Initialize secret scrubber.
	scrubber, err := scrub.New(cfg.Scrubbing.ExtraPatterns)
	if err != nil {
		return nil, fmt.Errorf("classifier: init scrubber: %w", err)
	}

	// Initialize LLM provider (nil if no auth available).
	var provider llm.ReviewerProvider
	var providerType string
	switch strings.ToLower(strings.TrimSpace(cfg.LLM.Provider)) {
	case "", "anthropic":
		ap := llm.NewAnthropicProvider()
		if ap.HasAuth() {
			provider = ap
			if ap.IsSDK() {
				providerType = "anthropic_sdk"
			} else {
				providerType = "oauth_subprocess"
			}
		}
	default:
		return nil, fmt.Errorf("classifier: unsupported LLM provider %q", cfg.LLM.Provider)
	}

	// Wrap with rate limiter — delegates enable/disable semantics to the
	// rate-limited provider itself (<= 0 = disabled, i.e., max_calls_per_minute = 0 in config).
	if provider != nil {
		maxCalls := 0 // default: disabled if pointer is nil (test/embedded configs)
		if cfg.LLM.MaxCallsPerMinute != nil {
			maxCalls = *cfg.LLM.MaxCallsPerMinute
		}
		provider = llm.NewRateLimitedProvider(provider, maxCalls)
	}

	// Fallback for configs not created via Load (tests, embedded).
	serverCWD := cfg.ServerCWD
	if serverCWD == "" {
		if cwd, err := os.Getwd(); err == nil {
			serverCWD = cwd
		}
	}

	// Initialize corpus if enabled.
	var c *corpus.Corpus
	if cfg.Corpus.IsEnabled() {
		var err2 error
		c, err2 = corpus.Open(context.Background(), cfg.Corpus)
		if err2 != nil {
			return nil, fmt.Errorf("classifier: open corpus: %w", err2)
		}
	}

	// Create a classifier-lifecycle context so background goroutines started
	// by CommandCache and feedback.Handler are properly stopped on Close.
	lifecycleCtx, cancel := context.WithCancel(context.Background())

	// Initialize command cache.
	var cacheTTL time.Duration
	if cfg.Corpus.CommandCacheTTL != "" {
		var parseErr error
		cacheTTL, parseErr = time.ParseDuration(cfg.Corpus.CommandCacheTTL)
		if parseErr != nil {
			cancel()
			if c != nil {
				c.Close()
			}
			return nil, fmt.Errorf("classifier: invalid command_cache_ttl %q: %w", cfg.Corpus.CommandCacheTTL, parseErr)
		}
	}
	var cmdCache *CommandCache
	if cfg.Corpus.IsCommandCacheEnabled() {
		cmdCache = NewCommandCache(lifecycleCtx, cacheTTL, cfg.Corpus.CommandCacheMaxEntries)
	} else {
		cmdCache = NewCommandCache(lifecycleCtx, 0, 0) // no-op cache
	}

	// Generate HMAC secret for feedback tokens.
	hmacSecret, err := feedback.GenerateSecret()
	if err != nil {
		cancel()
		if c != nil {
			c.Close()
		}
		return nil, fmt.Errorf("classifier: generate HMAC secret: %w", err)
	}

	// Parse corpus max age once (used on every LLM review, avoid per-request parsing).
	corpusMaxAge := 90 * 24 * time.Hour // default
	if parsed, err := config.ParseMaxAge(cfg.Corpus.MaxAge); err == nil && parsed > 0 {
		corpusMaxAge = parsed
	}

	// Create feedback handler.
	feedbackHandler := feedback.NewHandler(lifecycleCtx, c, hmacSecret, cfg.Corpus.IsStoreUserApprovals())

	return &Classifier{
		engine:          eng,
		walkerCfg:       wc,
		dialect:         cfg.Parser.Dialect,
		maxCmdLen:       cfg.Classifier.MaxCommandLength,
		maxASTDepth:     cfg.Classifier.MaxASTDepth,
		unresolvable:    cfg.Classifier.UnresolvableExpansion,
		version:         cmp.Or(cfg.Version, "dev"),
		llmProvider:     provider,
		llmProviderType: providerType,
		scrubber:        scrubber,
		llmCfg:          cfg.LLM,
		corpusCfg:       cfg.Corpus,
		corpusMaxAge:    corpusMaxAge,
		scopes:          cfg.Scopes,
		serverCWD:       serverCWD,
		maxReasonLen:    derefIntOr(cfg.LLM.MaxResponseReasoningLength, 200),
		corpus:          c,
		cmdCache:        cmdCache,
		feedbackHandler: feedbackHandler,
		hmacSecret:      hmacSecret,
		cancel:          cancel,
		tel:             &telemetry.NoOpTelemetry{},
	}, nil
}

// SetTelemetry injects a Telemetry implementation. Must be called before
// the first Classify call. Not thread-safe — call during initialization only.
// Nil is treated as NoOp.
func (c *Classifier) SetTelemetry(t telemetry.Telemetry) {
	if t == nil {
		t = &telemetry.NoOpTelemetry{}
	}
	c.tel = t
}

// LLMProviderType returns the LLM provider type string for health reporting.
// Returns "" if no provider is configured.
func (c *Classifier) LLMProviderType() string {
	return c.llmProviderType
}

// NewWithProvider creates a Classifier with an explicit LLM provider.
// Used for testing with mock providers.
func NewWithProvider(cfg *config.Config, provider llm.ReviewerProvider) (*Classifier, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	c.llmProvider = provider
	return c, nil
}

// classifyState holds all request-scoped data for a single Classify() call.
// Derived values (signatures, scrubbed command) are computed lazily on first access.
type classifyState struct {
	ctx     context.Context
	req     ClassifyRequest
	cmds    []rules.CommandInfo
	resp    *ClassifyResponse
	traceID string
	debug   *DebugInfo // non-nil when DryRun=true

	// Lazily computed structural fields.
	sigComputed   bool
	signature     string
	signatureHash string
	cmdNames      []string
	cmdFlags      []string
}

// ensureSignature computes the structural signature if not already done.
func (s *classifyState) ensureSignature() {
	if s.sigComputed {
		return
	}
	s.signature, s.signatureHash = corpus.ComputeSignature(s.cmds)
	s.cmdNames = corpus.CommandNames(s.cmds)
	s.cmdFlags = collectFlags(s.cmds)
	s.sigComputed = true
}

// Classify runs the classification pipeline and returns a response.
// It never returns nil.
func (c *Classifier) Classify(ctx context.Context, req ClassifyRequest) *ClassifyResponse {
	start := time.Now()

	// Start classify span — OTel TraceID becomes stargate_trace_id when available.
	ctx, span := c.tel.StartClassifySpan(ctx)
	defer span.End()

	// Dry-run requests (/test endpoint) tag their spans so operators can
	// filter test traffic from real classifications in Grafana dashboards.
	if req.DryRun {
		span.SetAttributes(attribute.Bool("stargate.dry_run", true))
	}

	traceID := c.tel.TraceIDFromContext(ctx)
	if traceID == "" {
		traceID = newTraceID() // fallback when telemetry disabled
	}

	// Store tool_use_id → trace_id for feedback correlation.
	if req.Context != nil {
		if toolUseID, ok := req.Context["tool_use_id"].(string); ok && toolUseID != "" {
			c.tel.StoreToolUseTrace(toolUseID, traceID)
		}
	}

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
		Version: c.version,
	}

	finalize := func() *ClassifyResponse {
		resp.Timing.TotalMs = float64(time.Since(start).Microseconds()) / 1000
		// Skip classification metrics for dry-run: /test traffic is a
		// developer tool and should not inflate production dashboards
		// (stargate_classifications_total, stargate_classify_duration).
		// The span still carries stargate.dry_run=true for trace filtering.
		if !req.DryRun {
			ruleLevel := "none"
			if resp.Rule != nil {
				ruleLevel = resp.Rule.Level
			}
			c.tel.RecordClassification(resp.Decision, ruleLevel, resp.Timing.TotalMs)
		}
		return resp
	}

	// Debug fields are populated inline at each pipeline stage, guarded by
	// state.debug != nil. No recover() — a panic in debug code should surface
	// the same as any other bug, not be silently swallowed.
	if req.DryRun {
		resp.Debug = &DebugInfo{
			ScrubbedCommand: c.scrubber.Command(req.Command),
		}
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

	// Build classify state — lazy signature computation defers work until needed.
	state := &classifyState{
		ctx:     ctx,
		req:     req,
		cmds:    cmds,
		resp:    resp,
		traceID: traceID,
		debug:   resp.Debug, // nil for non-DryRun
	}

	// 4. Rule engine evaluation.
	// Unresolvable commands (Name == "") never match command/commands rules,
	// so they fail GREEN and fall to YELLOW/default. RED rules still fire for
	// other commands in the same input (e.g., "$(echo rm); rm -rf /").
	rulesStart := time.Now()
	var result *rules.Result
	if req.DryRun {
		result = c.engine.EvaluateWithTrace(ctx, cmds, req.Command, req.CWD)
	} else {
		result = c.engine.Evaluate(ctx, cmds, req.Command, req.CWD)
	}
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

	if resp.Debug != nil {
		resp.Debug.RuleTrace = result.Trace
	}

	resp.Decision = result.Decision
	resp.Action = result.Action
	resp.Reason = result.Reason
	resp.Rule = result.Rule

	// 6. LLM review — only for YELLOW decisions with llm_review=true.
	// The decision check guards against unresolvable_expansion overriding a
	// yellow default to red/green while LLMReview remains set.
	// Signature computed lazily inside reviewWithLLM (after cache miss).
	if result.Decision == "yellow" && result.LLMReview && c.llmProvider != nil {
		llmResult := c.reviewWithLLM(state)
		resp.LLMReview = llmResult
		resp.Timing.LLMMs = llmResult.DurationMs

		if !llmResult.Performed {
			// Cache hit: action is already computed from the cached entry.
			resp.Action = llmResult.Action
			resp.Reason = "cached classification (no LLM call)"
		} else {
			// Map live LLM decision to action.
			switch llmResult.Decision {
			case "allow":
				resp.Action = "allow"
				resp.Reason = llmReasonString("LLM review approved", llmResult.Reasoning)
			case "deny":
				resp.Action = "block"
				resp.Reason = llmReasonString("LLM review denied", llmResult.Reasoning)
			default:
				// Invalid/empty decision → ask user (fail-closed).
				resp.Action = "review"
				resp.Reason = "LLM review returned invalid/empty decision; defaulting to review (fail-closed)"
			}
		}
	}

	// 7. Generate feedback token for YELLOW decisions — only when tool_use_id
	// is present. Without it we cannot correlate feedback to a specific tool
	// invocation, so we skip token generation and trace recording entirely.
	//
	// Dry-run: never generate a feedback token (the /test caller is a developer
	// inspecting classification behavior, not an agent that will return feedback).
	if resp.Decision == "yellow" && !req.DryRun {
		toolUseID := ""
		if req.Context != nil {
			if v, ok := req.Context["tool_use_id"].(string); ok {
				toolUseID = v
			}
		}
		if toolUseID != "" {
			// Compute structural fields if not already done (LLM path skipped when
			// provider is nil, but feedback still needs them for user_approved entries).
			state.ensureSignature()
			token := feedback.GenerateToken(c.hmacSecret, traceID, toolUseID, resp.Decision)
			resp.FeedbackToken = &token
			if c.feedbackHandler != nil {
				sessionID, agent := "", ""
				if req.Context != nil {
					if v, ok := req.Context["session_id"].(string); ok {
						sessionID = v
					}
					if v, ok := req.Context["agent"].(string); ok {
						agent = v
					}
				}
				c.feedbackHandler.RecordTrace(feedback.TraceInfo{
					Decision:      resp.Decision,
					ToolUseID:     toolUseID,
					TraceID:       traceID,
					Signature:     state.signature,
					SignatureHash: state.signatureHash,
					CommandNames:  state.cmdNames,
					Flags:         state.cmdFlags,
					RawCommand:    c.scrubber.Command(req.Command),
					CWD:           req.CWD,
					SessionID:     sessionID,
					Agent:         agent,
				})
			}
		}
	}

	return finalize()
}

// reviewWithLLM runs the LLM review pipeline: cache → corpus → scrub → prompt → call → (files → call) → corpus write → cache write.
func (c *Classifier) reviewWithLLM(state *classifyState) *LLMReviewResult {
	llmStart := time.Now()
	result := &LLMReviewResult{
		Performed:      true,
		Rounds:         1,
		RiskFactors:    []string{},
		FilesRequested: []string{},
		FilesInspected: []string{},
	}

	defer func() {
		result.DurationMs = float64(time.Since(llmStart).Microseconds()) / 1000
	}()

	// Command cache check — skip everything on HIT.
	// This must return before postProcess is defined so cache hits never
	// write to corpus or command cache.
	//
	// Dry-run: skip cache reads by default. When UseCache=true (operator
	// explicitly wants to test cache behavior), allow reads. Cache writes
	// are always skipped in dry-run via the guard in postProcess.
	cacheAllowed := !state.req.DryRun || state.req.UseCache
	if state.debug != nil {
		state.debug.Cache = &CacheDebug{Checked: cacheAllowed}
	}
	if cacheAllowed {
		if cached, hit := c.cmdCache.Lookup(state.req.Command, state.req.CWD); hit {
			if state.debug != nil {
				state.debug.Cache.Hit = true
				state.debug.Cache.Entry = &CacheEntryDebug{
					Decision: cached.Decision,
					Action:   cached.Action,
				}
			}
			result.Performed = false
			result.Rounds = 0
			result.Decision = cached.Decision
			result.Action = cached.Action
			result.Reasoning = "command cache hit (no LLM call)"
			return result
		}
	}

	// Populate corpus summary in response — declared before postProcess so
	// the closure can mark EntryWritten.
	corpusSummary := &CorpusSummary{}
	state.resp.Corpus = corpusSummary

	// postProcess writes to corpus and command cache after LLM decision.
	// It no-ops when result.Decision is empty (error paths), so deferred
	// calls on error returns are safe.
	postProcess := func() {
		if result.Decision == "" {
			return // no decision to store (LLM error)
		}

		// Dry-run: skip all side effects (corpus write, cache write).
		if state.req.DryRun {
			return
		}

		// Validate LLM decision before persisting — unexpected values from the
		// LLM (e.g., "maybe") should not pollute the corpus or command cache.
		validDecision := result.Decision == "allow" || result.Decision == "deny"
		if !validDecision {
			return // skip corpus/cache write for invalid decisions
		}

		// Write judgment to corpus (scrubbed, rate-limited).
		if c.corpus != nil {
			// Check store_decisions filter.
			shouldStore := true
			switch c.corpusCfg.StoreDecisions {
			case "allow_only":
				shouldStore = result.Decision == "allow"
			case "deny_only":
				shouldStore = result.Decision == "deny"
			case "all", "":
				shouldStore = true
			}
			if shouldStore {
				// Compute scrubbed command and AST summary for corpus entry.
				// These are cheap operations, computed here to avoid variable
				// ordering dependencies with the defer.
				scrubbedCmd := c.scrubber.Command(state.req.Command)
				astSummary := c.buildASTTextSummary(state.cmds)

				// Extract caller context for corpus entry.
				var sessionID, agent string
				if state.req.Context != nil {
					if v, ok := state.req.Context["session_id"].(string); ok {
						sessionID = v
					}
					if v, ok := state.req.Context["agent"].(string); ok {
						agent = v
					}
				}
				entry := corpus.PrecedentEntry{
					Signature:     state.signature,
					SignatureHash: state.signatureHash,
					CommandNames:  state.cmdNames,
					Flags:         state.cmdFlags,
					ASTSummary:    astSummary,
					CWD:           state.req.CWD,
					Decision:      result.Decision,
					TraceID:       state.resp.StargateTrID,
					SessionID:     sessionID,
					Agent:         agent,
				}
				if c.corpusCfg.IsStoreRawCommand() {
					entry.RawCommand = scrubbedCmd
				}
				if c.corpusCfg.IsStoreReasoning() {
					entry.Reasoning = truncateStr(result.Reasoning, c.corpusCfg.MaxReasoningLength)
				}
				entry.RiskFactors = result.RiskFactors
				if err := c.corpus.Write(entry); err != nil {
					if !errors.Is(err, corpus.ErrRateLimited) {
						fmt.Fprintf(os.Stderr, "classifier: corpus write: %v\n", err)
					}
				} else {
					corpusSummary.EntryWritten = true
				}
			}
		}

		// Write to command cache.
		action := ""
		switch result.Decision {
		case "allow":
			action = "allow"
		case "deny":
			action = "block"
		default:
			action = "review"
		}
		c.cmdCache.Store(state.req.Command, state.req.CWD, result.Decision, action)
	}
	defer postProcess()

	// Corpus precedent lookup.
	state.ensureSignature()
	var precedentText string
	var precedentsFound int
	if c.corpus != nil {
		lookupCfg := corpus.LookupConfig{
			MinSimilarity:  c.corpusCfg.MinSimilarity,
			MaxPrecedents:  c.corpusCfg.MaxPrecedents,
			MaxPerPolarity: c.corpusCfg.MaxPrecedentsPerPolarity,
			MaxAge:         c.corpusMaxAge,
		}
		precedents, err := c.corpus.LookupSimilar(state.cmdNames, state.signature, lookupCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "classifier: corpus lookup: %v\n", err)
		} else {
			precedentsFound = len(precedents)
			if state.debug != nil && len(precedents) > 0 {
				for _, p := range precedents {
					state.debug.PrecedentsInjected = append(state.debug.PrecedentsInjected, PrecedentDebug{
						ID:           fmt.Sprintf("%d", p.ID),
						Decision:     p.Decision,
						Similarity:   p.Similarity,
						CommandNames: p.CommandNames,
						Flags:        p.Flags,
						AgeSeconds:   int64(time.Since(p.CreatedAt).Seconds()),
					})
				}
			}
			// Format precedents for prompt.
			var fmtPrecedents []corpus.FormatPrecedent
			for _, p := range precedents {
				fmtPrecedents = append(fmtPrecedents, corpus.FormatPrecedent{
					Decision:   p.Decision,
					Command:    cmp.Or(p.RawCommand, "[scrubbed]"),
					Reasoning:  p.Reasoning,
					CWD:        p.CWD,
					CreatedAt:  p.CreatedAt,
					Similarity: p.Similarity,
					ExactMatch: p.SignatureHash == state.signatureHash,
				})
			}
			precedentText = corpus.FormatPrecedents(fmtPrecedents)
		}
	}
	corpusSummary.PrecedentsFound = precedentsFound

	// Scrub command and build AST summary for prompt.
	scrubbedCmd := c.scrubber.Command(state.req.Command)
	astSummary := c.buildASTTextSummary(state.cmds)

	// Format scopes for prompt (sorted for deterministic ordering).
	scopeNames := make([]string, 0, len(c.scopes))
	for name := range c.scopes {
		scopeNames = append(scopeNames, name)
	}
	slices.Sort(scopeNames)
	var scopeLines []string
	for _, name := range scopeNames {
		scopeLines = append(scopeLines, name+": "+strings.Join(c.scopes[name], ", "))
	}

	vars := llm.PromptVars{
		Command:    scrubbedCmd,
		ASTSummary: astSummary,
		CWD:        state.req.CWD,
		RuleReason: state.resp.Reason,
		Scopes:     strings.Join(scopeLines, "\n"),
		Precedents: precedentText,
	}

	systemPrompt, userContent := llm.BuildPrompt(c.llmCfg.SystemPrompt, vars)
	if state.debug != nil {
		state.debug.RenderedPrompts = &PromptDebug{
			System: systemPrompt,
			User:   userContent,
		}
	}

	// First LLM call.
	llmReq := llm.ReviewRequest{
		SystemPrompt: systemPrompt,
		UserContent:  userContent,
		Model:        c.llmCfg.Model,
		MaxTokens:    c.llmCfg.MaxTokens,
		Temperature:  c.llmCfg.Temperature,
	}

	llmResp, err := c.llmProvider.Review(state.ctx, llmReq)
	if state.debug != nil && llmResp.RawBody != "" {
		state.debug.LLMRawResponse = llmResp.RawBody
	}
	if err != nil {
		if errors.Is(err, llm.ErrRateLimited) {
			result.Reasoning = truncateStr("LLM rate limit exceeded", c.maxReasonLen)
		} else {
			result.Reasoning = truncateStr("LLM call failed", c.maxReasonLen)
		}
		// Fail-closed: fall back to ask user.
		return result
	}

	// If verdict, we're done. Scrub reasoning/risk_factors — the LLM may
	// echo secrets from the command or file contents in its response.
	if len(llmResp.RequestFiles) == 0 {
		result.Decision = llmResp.Decision
		result.Reasoning = truncateStr(c.scrubber.Text(llmResp.Reasoning), c.maxReasonLen)
		result.RiskFactors = c.scrubRiskFactors(llmResp.RiskFactors)
		return result
	}

	// File retrieval round.
	result.FilesRequested = llmResp.RequestFiles

	if !c.llmCfg.AllowFileRetrieval {
		// File retrieval disabled — return first-call response, no second call.
		result.Decision = llmResp.Decision
		result.Reasoning = truncateStr(c.scrubber.Text(llmResp.Reasoning), c.maxReasonLen)
		return result
	}

	result.Rounds = 2

	fileCfg := llm.FileResolverConfig{
		AllowedPaths:      c.llmCfg.AllowedPaths,
		DeniedPaths:       c.llmCfg.DeniedPaths,
		MaxFileSize:       c.llmCfg.MaxFileSize,
		MaxFilesPerReq:    c.llmCfg.MaxFilesPerRequest,
		MaxTotalFileBytes: c.llmCfg.MaxTotalFileBytes,
		ServerCWD:         c.serverCWD,
		Scrubber:          c.scrubber,
	}

	fileResults := llm.ResolveFiles(llmResp.RequestFiles, fileCfg)

	// Build file contents block and track inspected files.
	var fileContentParts []string
	for _, fr := range fileResults {
		if fr.Absent {
			fileContentParts = append(fileContentParts, fmt.Sprintf("### %s\n[file not available]", fr.Label))
			continue
		}
		result.FilesInspected = append(result.FilesInspected, fr.FullPath)
		header := fmt.Sprintf("### %s", fr.Label)
		if fr.Truncated {
			header += " [truncated]"
		}
		fileContentParts = append(fileContentParts, header+"\n"+fr.Content)
	}

	// Rebuild prompt with file contents.
	vars.FileContents = strings.Join(fileContentParts, "\n\n")
	systemPrompt2, userContent2 := llm.BuildPrompt(c.llmCfg.SystemPrompt, vars)
	llmReq.SystemPrompt = systemPrompt2
	llmReq.UserContent = userContent2

	// Second LLM call.
	llmResp2, err := c.llmProvider.Review(state.ctx, llmReq)
	if state.debug != nil {
		state.debug.RenderedPrompts = &PromptDebug{
			System: systemPrompt2,
			User:   userContent2,
		}
		if llmResp2.RawBody != "" {
			state.debug.LLMRawResponse = llmResp2.RawBody
		}
	}
	if err != nil {
		result.Reasoning = truncateStr("Second LLM call failed", c.maxReasonLen)
		return result
	}

	// Second call MUST return a verdict — another file request → deny.
	if len(llmResp2.RequestFiles) > 0 {
		result.Decision = "deny"
		result.Reasoning = truncateStr("LLM requested files again (two-call maximum enforced)", c.maxReasonLen)
		return result
	}

	result.Decision = llmResp2.Decision
	result.Reasoning = truncateStr(c.scrubber.Text(llmResp2.Reasoning), c.maxReasonLen)
	result.RiskFactors = c.scrubRiskFactors(llmResp2.RiskFactors)
	return result
}

// scrubRiskFactors runs each risk factor through the secret scrubber.
func (c *Classifier) scrubRiskFactors(factors []string) []string {
	if factors == nil {
		return nil
	}
	out := make([]string, len(factors))
	for i, f := range factors {
		out[i] = c.scrubber.Text(f)
	}
	return out
}

// buildASTTextSummary produces a human-readable text summary of the AST
// for inclusion in the LLM prompt.
func (c *Classifier) buildASTTextSummary(cmds []rules.CommandInfo) string {
	var parts []string
	for _, cmd := range cmds {
		scrubbedCmd := c.scrubber.CommandInfo(cmd)
		line := scrubbedCmd.Name
		if scrubbedCmd.Subcommand != "" {
			line += " " + scrubbedCmd.Subcommand
		}
		if len(scrubbedCmd.Flags) > 0 {
			line += " flags=" + strings.Join(scrubbedCmd.Flags, ",")
		}
		if len(scrubbedCmd.Args) > 0 {
			line += " args=" + strings.Join(scrubbedCmd.Args, ",")
		}
		line += " context=" + contextLabel(scrubbedCmd.Context)
		parts = append(parts, line)
	}
	return strings.Join(parts, "\n")
}

func derefIntOr(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
}

// truncateStr truncates s to maxLen runes, appending "..." when truncated.
// maxLen == 0 returns "" (spec: "Set to 0 to omit reasoning entirely").
// maxLen < 0 returns s unchanged (no limit).
// Uses rune count to avoid splitting multi-byte UTF-8 sequences.
func truncateStr(s string, maxLen int) string {
	if maxLen == 0 {
		return ""
	}
	if maxLen < 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// llmReasonString builds a reason string from a prefix and reasoning.
// When reasoning is empty (e.g., max_response_reasoning_length=0), returns
// just the prefix without a trailing ": ".
func llmReasonString(prefix, reasoning string) string {
	if reasoning == "" {
		return prefix
	}
	return prefix + ": " + truncateStr(reasoning, 200)
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
	return contextLabel(cmd.Context)
}

// contextLabel derives a human-readable context label from a CommandContext.
func contextLabel(ctx rules.CommandContext) string {
	switch {
	case ctx.InSubstitution:
		return "substitution"
	case ctx.InCondition:
		return "condition"
	case ctx.InFunction != "":
		return "function"
	case ctx.SubshellDepth > 0:
		return "subshell"
	case ctx.PipelinePosition == 1:
		return "pipeline_source"
	case ctx.PipelinePosition >= 2:
		return "pipeline_sink"
	default:
		return "top_level"
	}
}


// HandleFeedback is the HTTP handler for POST /feedback. If the feedback
// handler was not initialized (e.g., classifier created without HMAC secret),
// it returns 501 Not Implemented. When the corpus is nil but the handler exists,
// feedback is accepted but not persisted (best-effort).
// The server registers this directly — it never needs to know about the
// feedback package or the classifier's internal structure.
func (c *Classifier) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	if c.feedbackHandler != nil {
		c.feedbackHandler.HandleFeedback(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"}) //nolint:errcheck
}

// Close releases resources held by the classifier (corpus DB, background goroutines).
// It cancels the classifier-lifecycle context (stopping CommandCache and feedback
// Handler goroutines) and then closes the corpus database.
func (c *Classifier) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.corpus != nil {
		return c.corpus.Close()
	}
	return nil
}

// collectFlags gathers all flags from all commands for corpus storage.
func collectFlags(cmds []rules.CommandInfo) []string {
	seen := make(map[string]struct{})
	var flags []string
	for _, cmd := range cmds {
		for _, f := range cmd.Flags {
			if _, ok := seen[f]; !ok {
				seen[f] = struct{}{}
				flags = append(flags, f)
			}
		}
	}
	return flags
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
