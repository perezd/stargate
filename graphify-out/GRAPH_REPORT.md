# Graph Report - .  (2026-04-29)

## Corpus Check
- 100 files · ~137,334 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1263 nodes · 3175 edges · 45 communities detected
- Extraction: 58% EXTRACTED · 42% INFERRED · 0% AMBIGUOUS · INFERRED: 1349 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_API & Adapter Layer|API & Adapter Layer]]
- [[_COMMUNITY_Explain & Corpus Display|Explain & Corpus Display]]
- [[_COMMUNITY_Classifier Telemetry & Config|Classifier Telemetry & Config]]
- [[_COMMUNITY_Test CLI & Precedent Format|Test CLI & Precedent Format]]
- [[_COMMUNITY_Cache & Command Classification|Cache & Command Classification]]
- [[_COMMUNITY_Hook Adapter Protocol|Hook Adapter Protocol]]
- [[_COMMUNITY_Rule Engine Core|Rule Engine Core]]
- [[_COMMUNITY_Evasion Detection Tests|Evasion Detection Tests]]
- [[_COMMUNITY_Config & Init Commands|Config & Init Commands]]
- [[_COMMUNITY_LLM Review Pipeline|LLM Review Pipeline]]
- [[_COMMUNITY_Feedback & Trace Recording|Feedback & Trace Recording]]
- [[_COMMUNITY_Classifier Unit Tests|Classifier Unit Tests]]
- [[_COMMUNITY_Anthropic LLM Provider|Anthropic LLM Provider]]
- [[_COMMUNITY_Security Framework Docs|Security Framework Docs]]
- [[_COMMUNITY_Accepted Risk Registry|Accepted Risk Registry]]
- [[_COMMUNITY_Config Schema & Defaults|Config Schema & Defaults]]
- [[_COMMUNITY_GitHub Owner Resolution|GitHub Owner Resolution]]
- [[_COMMUNITY_File Retrieval & Scrubbing|File Retrieval & Scrubbing]]
- [[_COMMUNITY_Debug Observability Plan|Debug Observability Plan]]
- [[_COMMUNITY_Corpus Signature Hashing|Corpus Signature Hashing]]
- [[_COMMUNITY_Fence Tag Stripping|Fence Tag Stripping]]
- [[_COMMUNITY_Telemetry Logger Tests|Telemetry Logger Tests]]
- [[_COMMUNITY_Architecture & Specs|Architecture & Specs]]
- [[_COMMUNITY_Classifier Debug Types|Classifier Debug Types]]
- [[_COMMUNITY_URL Scope Resolution|URL Scope Resolution]]
- [[_COMMUNITY_Config Specification|Config Specification]]
- [[_COMMUNITY_Milestone Retrospectives|Milestone Retrospectives]]
- [[_COMMUNITY_LLM Reviewer Interface|LLM Reviewer Interface]]
- [[_COMMUNITY_Corpus Admin & Stats|Corpus Admin & Stats]]
- [[_COMMUNITY_Eval Context Concepts|Eval Context Concepts]]
- [[_COMMUNITY_Test Endpoint Server|Test Endpoint Server]]
- [[_COMMUNITY_Trust Model Docs|Trust Model Docs]]
- [[_COMMUNITY_Panel Review Process|Panel Review Process]]
- [[_COMMUNITY_Green Rule Testdata|Green Rule Testdata]]
- [[_COMMUNITY_Fly.io Debug Context|Fly.io Debug Context]]
- [[_COMMUNITY_Agent Adapter Spec|Agent Adapter Spec]]
- [[_COMMUNITY_OpenTelemetry Deps|OpenTelemetry Deps]]
- [[_COMMUNITY_Red Rule Testdata|Red Rule Testdata]]
- [[_COMMUNITY_Yellow Rule Testdata|Yellow Rule Testdata]]
- [[_COMMUNITY_Shell AST Parsing Docs|Shell AST Parsing Docs]]
- [[_COMMUNITY_Scopes Package|Scopes Package]]
- [[_COMMUNITY_SQLite Dependency|SQLite Dependency]]
- [[_COMMUNITY_Integration Test Plan|Integration Test Plan]]
- [[_COMMUNITY_Architecture Spec|Architecture Spec]]
- [[_COMMUNITY_Fail-Closed Design|Fail-Closed Design]]

## God Nodes (most connected - your core abstractions)
1. `walk()` - 61 edges
2. `ParseAndWalk()` - 59 edges
3. `findByName()` - 54 edges
4. `New()` - 52 edges
5. `testConfig()` - 39 edges
6. `NewEngine()` - 36 edges
7. `mustNewServer()` - 33 edges
8. `newClassifier()` - 24 edges
9. `HandlePreToolUse()` - 23 edges
10. `parseTestFlags()` - 22 edges

## Surprising Connections (you probably didn't know these)
- `Contextual Trust Layer - Scopes and Resolvers` --semantically_similar_to--> `Scopes and Resolvers - Contextual Trust Design`  [INFERRED] [semantically similar]
  CLAUDE.md → docs/superpowers/specs/2026-04-06-stargate-design.md
- `AST Parsing Layer - mvdan.cc/sh/v3 Shell Parser` --semantically_similar_to--> `Shell Parser: mvdan.cc/sh/v3/syntax - AST Node Coverage`  [INFERRED] [semantically similar]
  CLAUDE.md → docs/superpowers/specs/2026-04-06-stargate-design.md
- `Rule Engine Layer - TOML-Defined RED/GREEN/YELLOW Rules` --semantically_similar_to--> `Rule Matching Logic - Field Matching, Flag Normalization, Evaluation Order`  [INFERRED] [semantically similar]
  CLAUDE.md → docs/superpowers/specs/2026-04-06-stargate-design.md
- `LLM Review Layer - Provider-Agnostic Classification` --semantically_similar_to--> `LLM Review Protocol - Two-Call File Retrieval with Scrubbing`  [INFERRED] [semantically similar]
  CLAUDE.md → docs/superpowers/specs/2026-04-06-stargate-design.md
- `TestNewInvalidPattern()` --calls--> `New()`  [INFERRED]
  /Users/derek/src/stargate/internal/scrub/scrub_test.go → /Users/derek/src/stargate/internal/classifier/classifier.go

## Hyperedges (group relationships)
- **Defense-in-Depth Security Layers: AST + Rules + Scopes + LLM** — claude_md_ast_parsing_layer, claude_md_rule_engine_layer, claude_md_contextual_trust_layer, claude_md_llm_review_layer, claude_md_defense_in_depth [EXTRACTED 1.00]
- **Implementation Milestone Progression with Retrospectives** — plan_m0_skeleton, plan_m1_parser_walker, plan_m1_retrospective, plan_m2_rule_engine, plan_m2_retrospective, plan_m3_scopes_resolvers, plan_m3_retrospective, plan_m4_llm_review, plan_m4_retrospective [EXTRACTED 1.00]
- **Classification Pipeline Flow: Parse -> Rules -> Cache -> Corpus -> LLM -> Decision** — spec_classification_pipeline, spec_ast_walking, spec_rule_matching, spec_command_cache, spec_structural_signatures, spec_llm_review_protocol, spec_secret_scrubbing [EXTRACTED 1.00]

## Communities

### Community 0 - "API & Adapter Layer"
Cohesion: 0.04
Nodes (92): ClassifyRequest, ClassifyResponse, ClientConfig, FeedbackBody, FeedbackRequest, TestRecent_Basic(), TestRecent_DefaultLimit(), TestRecent_Empty() (+84 more)

### Community 1 - "Explain & Corpus Display"
Cohesion: 0.05
Nodes (97): truncate(), buildRuleSummary(), fetchExplain(), filterRuleTrace(), formatLevelTag(), handleExplain(), isRelevantEntry(), parseExplainFlags() (+89 more)

### Community 2 - "Classifier Telemetry & Config"
Cohesion: 0.04
Nodes (56): testTelemetry, RedactedString, severityFromDecision(), TestTruncateBytes(), truncateBytes(), initMetrics(), collectMetrics(), findCounter() (+48 more)

### Community 3 - "Test CLI & Precedent Format"
Cohesion: 0.05
Nodes (80): FormatPrecedent, ageLabel(), decisionLabel(), FormatPrecedents(), matchLabel(), TestFormatPrecedents_DenyDecision(), TestFormatPrecedents_Empty(), TestFormatPrecedents_EmptyCWDOmitted() (+72 more)

### Community 4 - "Cache & Command Classification"
Cohesion: 0.05
Nodes (59): cacheKey(), NewCommandCache(), TestCommandCache(), CachedDecision, CommandCache, New(), CorpusConfig, New() (+51 more)

### Community 5 - "Hook Adapter Protocol"
Cohesion: 0.07
Nodes (63): bashToolInput, hookOutput, hookOutputJSON, hookSpecificOutput, postToolUseInput, preToolUseInput, TraceData, TraceNotFoundError (+55 more)

### Community 6 - "Rule Engine Core"
Cohesion: 0.08
Nodes (54): compileRules(), decisionToAction(), isDecomposable(), matchArgs(), matchContext(), matchFlags(), matchScope(), NewEngine() (+46 more)

### Community 7 - "Evasion Detection Tests"
Cohesion: 0.09
Nodes (61): findByName(), hasNameStart(), TestEvasion_AliasRawName(), TestEvasion_AnsiCHexEscape(), TestEvasion_AnsiCMixed(), TestEvasion_AnsiCNullByteTruncation(), TestEvasion_AnsiCOctalEscape(), TestEvasion_AnsiCUnicodeEscape() (+53 more)

### Community 8 - "Config & Init Commands"
Cohesion: 0.08
Nodes (50): handleConfig(), handleConfigDump(), handleConfigRules(), handleConfigScopes(), handleConfigValidate(), Load(), printRule(), captureStdout() (+42 more)

### Community 9 - "LLM Review Pipeline"
Cohesion: 0.06
Nodes (38): NewResolverAdapter(), ASTSummary, buildASTSummary(), Classifier, ClassifyRequest, ClassifyResponse, classifyState, collectFlags() (+30 more)

### Community 10 - "Feedback & Trace Recording"
Cohesion: 0.09
Nodes (38): FeedbackRequest, Handler, TraceInfo, NewHandler(), TestHandleFeedbackExpiredTrace(), TestHandleFeedbackIdempotent(), TestHandleFeedbackInvalidHMAC(), TestHandleFeedbackMissingFields() (+30 more)

### Community 11 - "Classifier Unit Tests"
Cohesion: 0.12
Nodes (41): mockProvider, NewWithProvider(), reviewerFunc, boolPtr(), intPtr(), llmTestConfig(), newClassifier(), TestClassifyASTSummaryCommandsFound() (+33 more)

### Community 12 - "Anthropic LLM Provider"
Cohesion: 0.09
Nodes (28): HasCLI(), NewAnthropicProvider(), parseResponse(), subprocessArgs(), TestNewAnthropicProvider_NoAuth(), TestNewAnthropicProvider_ReviewWithoutAuth(), TestNewAnthropicProvider_WithEnvAPIKey(), TestParseResponse_Allow() (+20 more)

### Community 13 - "Security Framework Docs"
Cohesion: 0.06
Nodes (38): AST Parsing Layer - mvdan.cc/sh/v3 Shell Parser, Contextual Trust Layer - Scopes and Resolvers, Defense-in-Depth Rationale - No Single Layer Sufficient, Dependency: anthropic-sdk-go - Anthropic/Claude LLM Provider, Dependency: mvdan.cc/sh/v3 - Shell Parser and AST, LLM Review Layer - Provider-Agnostic Classification, Rule Engine Layer - TOML-Defined RED/GREEN/YELLOW Rules, Security Framework - Four Defense Layers (+30 more)

### Community 14 - "Accepted Risk Registry"
Cohesion: 0.06
Nodes (38): Accepted Risk: Adversarial Instructions in Corpus Reasoning, Accepted Risk: --allow-remote Without Transport Security, Accepted Risk: Base64-Encoded Secrets Not Detected by Scrubbing, Accepted Risk: files_requested Reveals LLM Reasoning Patterns, Accepted Risk: Precedent Reasoning Accumulation, Rationale: Balanced polarity injection, truncation, TTL decay bound adversarial corpus impact, Rationale: --allow-remote is explicit operator opt-in, not default, Rationale: Base64 detection too error-prone; LLM is classification tool not exfiltration channel (+30 more)

### Community 15 - "Config Schema & Defaults"
Cohesion: 0.08
Nodes (33): applyDefaults(), ClassifierConfig, CommandFlagsConfig, Config, DefaultCommandFlags(), DefaultWrappers(), LLMConfig, LogConfig (+25 more)

### Community 16 - "GitHub Owner Resolution"
Cohesion: 0.14
Nodes (33): ownerFromAPIPath(), ownerFromGitConfig(), ownerFromGitPath(), ownerFromGitURL(), ownerFromRepoFlag(), parseGitConfigOriginURL(), parseOwnerRepo(), ResolveGitHubRepoOwner() (+25 more)

### Community 17 - "File Retrieval & Scrubbing"
Cohesion: 0.24
Nodes (20): anchorPattern(), isAllowed(), ResolveFiles(), makeFile(), newScrubber(), realTempDir(), TestResolveFiles_AllowedPath(), TestResolveFiles_DeniedPath() (+12 more)

### Community 18 - "Debug Observability Plan"
Cohesion: 0.12
Nodes (20): Task 1: Rule Trace Types (RuleTraceEntry, RuleSnapshot, ResolveDebug), Task 2: Rule Engine Trace Support (EvaluateWithTrace), Task 3: Debug Types in Classifier (DebugInfo), Task 4: LLM Raw Response Surfacing (RawBody on ReviewResponse), Task 5: Classifier Debug Population (DryRun=true wiring), Task 6: /test Handler Debug Serialization (wrapper struct), Task 7: Corpus Recent() Query, Task 8: corpus recent CLI Command (+12 more)

### Community 19 - "Corpus Signature Hashing"
Cohesion: 0.26
Nodes (17): signatureTuple, CommandNames(), ComputeSignature(), contextLabel(), makeCmd(), pipeCtx(), TestCommandNames_DeduplicatesAndSorts(), TestCommandNames_Empty() (+9 more)

### Community 20 - "Fence Tag Stripping"
Cohesion: 0.23
Nodes (13): init(), StripFenceTags(), TestAllFenceTagNames(), TestCaseInsensitive(), TestIterationBound(), TestMixedContent(), TestNonFenceTagsPreserved(), TestRecursiveTagStripping() (+5 more)

### Community 21 - "Telemetry Logger Tests"
Cohesion: 0.31
Nodes (9): assertAttr(), newTestLogger(), recordAttrs(), TestLogClassification_AllAttributes(), TestLogClassification_LLMAttributesConditional(), TestLogClassification_ScopeResolvedTruncated(), TestLogClassification_ScrubCommandGated(), TestLogClassification_SeverityMapping() (+1 more)

### Community 22 - "Architecture & Specs"
Cohesion: 0.22
Nodes (9): Accepted Risk: tool_name Bypass via Agent Renaming, Debug & Observability Implementation Plan, Debug & Observability Design Spec, Rationale: No new HTTP endpoints - reuse existing /test for debug data, Stargate Implementation Plan, Claude Code Integration via pre/post tool-use hooks, Stargate - Bash Command Classifier for AI Coding Agents, Stargate Design Specification (PRD v0.2.0) (+1 more)

### Community 23 - "Classifier Debug Types"
Cohesion: 0.33
Nodes (5): CacheDebug, CacheEntryDebug, DebugInfo, PrecedentDebug, PromptDebug

### Community 24 - "URL Scope Resolution"
Cohesion: 0.47
Nodes (4): extractURLCandidate(), parseURLDomain(), ResolveURLDomain(), TestResolveURLDomain()

### Community 25 - "Config Specification"
Cohesion: 0.4
Nodes (5): Dependency: BurntSushi/toml - TOML Config Parsing, Trust Boundaries - stargate.toml as Root Trust Anchor, M0: Skeleton - CLI, Config, HTTP Server, /health, Configuration File Specification (stargate.toml), Rationale: TOML Config Format - Comments, Unambiguous Types

### Community 26 - "Milestone Retrospectives"
Cohesion: 0.4
Nodes (5): Milestone Transition Protocol - Design Verification, M1 Retrospective - 84 Threads, 20 Rounds, Underspecified Design, M2 Retrospective - 61 Threads, API Schema and Handler Hardening, M3 Retrospective - 28 Threads, Panel Review Effective, M4 Retrospective - 91 Threads, Split-PR Amplification

### Community 27 - "LLM Reviewer Interface"
Cohesion: 0.5
Nodes (3): ReviewerProvider, ReviewRequest, ReviewResponse

### Community 28 - "Corpus Admin & Stats"
Cohesion: 0.5
Nodes (3): RecentEntry, RecentFilter, Stats

### Community 29 - "Eval Context Concepts"
Cohesion: 0.5
Nodes (4): 8 matching steps in matchRule: command, subcommands, flags, args, scope, context, resolve, pattern, evalContext - per-invocation trace state, stack-local, never on Engine struct, Rationale: Per-invocation evalContext avoids Engine struct mutation for concurrency safety, Design: Rule Engine Trace (EvaluateWithTrace with per-invocation evalContext)

### Community 30 - "Test Endpoint Server"
Cohesion: 0.67
Nodes (2): testDebugResponse, TestRequest

### Community 31 - "Trust Model Docs"
Cohesion: 0.67
Nodes (3): Accepted Risk: Telemetry Env Var Overrides Bypass stargate.toml, Scope-Based Trust - operator-defined scopes in stargate.toml, stargate.toml - root trust anchor config file

### Community 32 - "Panel Review Process"
Cohesion: 1.0
Nodes (2): Panel Review Process - Synthetic Expert Panel, Security Design Checklist - 9 Required Items

### Community 33 - "Green Rule Testdata"
Cohesion: 1.0
Nodes (2): Green Commands Test Data - Safe Command Samples, Default GREEN Rules - Read-Only, Toolchains, Trusted Scopes

### Community 34 - "Fly.io Debug Context"
Cohesion: 1.0
Nodes (2): Debugging workflow: SSH to fly.io VMs, pull corpus + config, iterate with /test locally, Problem: No visibility into LLM inputs, rule traces, time-based queries, or formatted output

### Community 35 - "Agent Adapter Spec"
Cohesion: 1.0
Nodes (2): Agent Adapters - stargate hook Protocol Translation, Claude Code Adapter - PreToolUse/PostToolUse Hook Integration

### Community 36 - "OpenTelemetry Deps"
Cohesion: 1.0
Nodes (2): Dependency: go.opentelemetry.io/otel - OpenTelemetry SDK, Telemetry - OpenTelemetry Traces, Metrics, Logs to Grafana Cloud

### Community 37 - "Red Rule Testdata"
Cohesion: 1.0
Nodes (2): Red Commands Test Data - Dangerous Command Samples, Default RED Rules - Destructive, Privilege Escalation, Exfiltration

### Community 38 - "Yellow Rule Testdata"
Cohesion: 1.0
Nodes (2): Default YELLOW Rules - Network, Docker, Package Install, Shell, Yellow Commands Test Data - Ambiguous Command Samples

### Community 40 - "Shell AST Parsing Docs"
Cohesion: 1.0
Nodes (1): Shell AST Parsing via mvdan.cc/sh/v3

### Community 41 - "Scopes Package"
Cohesion: 1.0
Nodes (1): internal/scopes - Scope definitions, resolver interface

### Community 42 - "SQLite Dependency"
Cohesion: 1.0
Nodes (1): Dependency: modernc.org/sqlite - Pure-Go SQLite

### Community 43 - "Integration Test Plan"
Cohesion: 1.0
Nodes (1): Task 11: Integration Test and Final Verification

### Community 44 - "Architecture Spec"
Cohesion: 1.0
Nodes (1): Architecture - HTTP Server + Shell Parser + Rule Engine + LLM

### Community 45 - "Fail-Closed Design"
Cohesion: 1.0
Nodes (1): Fail-Closed Design - Parse Error, Timeout, Resolver Failure Handling

## Knowledge Gaps
- **150 isolated node(s):** `testFlags`, `testHTTPRequest`, `explainFlags`, `explainResult`, `subcommandHandler` (+145 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Test Endpoint Server`** (3 nodes): `test_endpoint.go`, `testDebugResponse`, `TestRequest`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Panel Review Process`** (2 nodes): `Panel Review Process - Synthetic Expert Panel`, `Security Design Checklist - 9 Required Items`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Green Rule Testdata`** (2 nodes): `Green Commands Test Data - Safe Command Samples`, `Default GREEN Rules - Read-Only, Toolchains, Trusted Scopes`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Fly.io Debug Context`** (2 nodes): `Debugging workflow: SSH to fly.io VMs, pull corpus + config, iterate with /test locally`, `Problem: No visibility into LLM inputs, rule traces, time-based queries, or formatted output`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Agent Adapter Spec`** (2 nodes): `Agent Adapters - stargate hook Protocol Translation`, `Claude Code Adapter - PreToolUse/PostToolUse Hook Integration`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `OpenTelemetry Deps`** (2 nodes): `Dependency: go.opentelemetry.io/otel - OpenTelemetry SDK`, `Telemetry - OpenTelemetry Traces, Metrics, Logs to Grafana Cloud`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Red Rule Testdata`** (2 nodes): `Red Commands Test Data - Dangerous Command Samples`, `Default RED Rules - Destructive, Privilege Escalation, Exfiltration`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Yellow Rule Testdata`** (2 nodes): `Default YELLOW Rules - Network, Docker, Package Install, Shell`, `Yellow Commands Test Data - Ambiguous Command Samples`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Shell AST Parsing Docs`** (1 nodes): `Shell AST Parsing via mvdan.cc/sh/v3`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Scopes Package`** (1 nodes): `internal/scopes - Scope definitions, resolver interface`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SQLite Dependency`** (1 nodes): `Dependency: modernc.org/sqlite - Pure-Go SQLite`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Integration Test Plan`** (1 nodes): `Task 11: Integration Test and Final Verification`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Architecture Spec`** (1 nodes): `Architecture - HTTP Server + Shell Parser + Rule Engine + LLM`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Fail-Closed Design`** (1 nodes): `Fail-Closed Design - Parse Error, Timeout, Resolver Failure Handling`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `New()` connect `Cache & Command Classification` to `API & Adapter Layer`, `Classifier Telemetry & Config`, `Test CLI & Precedent Format`, `Hook Adapter Protocol`, `Rule Engine Core`, `Config & Init Commands`, `LLM Review Pipeline`, `Feedback & Trace Recording`, `Classifier Unit Tests`, `Anthropic LLM Provider`, `Config Schema & Defaults`, `File Retrieval & Scrubbing`?**
  _High betweenness centrality (0.089) - this node is a cross-community bridge._
- **Why does `FormatPrecedents()` connect `Test CLI & Precedent Format` to `Explain & Corpus Display`, `Classifier Telemetry & Config`, `LLM Review Pipeline`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Why does `NewEngine()` connect `Rule Engine Core` to `GitHub Owner Resolution`, `LLM Review Pipeline`, `Test CLI & Precedent Format`, `Cache & Command Classification`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `walk()` (e.g. with `ParseAndWalk()` and `DefaultWalkerConfig()`) actually correct?**
  _`walk()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 57 inferred relationships involving `ParseAndWalk()` (e.g. with `handleCorpusSearch()` and `walk()`) actually correct?**
  _`ParseAndWalk()` has 57 INFERRED edges - model-reasoned connections that need verification._
- **Are the 48 inferred relationships involving `New()` (e.g. with `handleConfigDump()` and `runOffline()`) actually correct?**
  _`New()` has 48 INFERRED edges - model-reasoned connections that need verification._
- **Are the 18 inferred relationships involving `testConfig()` (e.g. with `TestTest_SameSchemaAsClassify()` and `TestTest_ASTAlwaysPopulated()`) actually correct?**
  _`testConfig()` has 18 INFERRED edges - model-reasoned connections that need verification._