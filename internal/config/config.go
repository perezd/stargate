// Package config provides TOML config loading and validation for stargate.
package config

import (
	"fmt"
	"os"
	"regexp"

	"github.com/BurntSushi/toml"
)

// validateRulePattern checks that a rule's regex pattern compiles.
func validateRulePattern(pattern string) error {
	if pattern == "" {
		return nil
	}
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return nil
}

// Config is the top-level configuration structure for stargate.
type Config struct {
	Server     ServerConfig              `toml:"server"`
	Parser     ParserConfig              `toml:"parser"`
	Classifier ClassifierConfig          `toml:"classifier"`
	Scopes     map[string][]string       `toml:"scopes"`
	Rules      RulesConfig               `toml:"rules"`
	LLM        LLMConfig                 `toml:"llm"`
	Scrubbing  ScrubbingConfig           `toml:"scrubbing"`
	Corpus     CorpusConfig              `toml:"corpus"`
	Telemetry  TelemetryConfig           `toml:"telemetry"`
	Log        LogConfig                 `toml:"log"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Listen  string `toml:"listen"`
	Timeout string `toml:"timeout"`
}

// ParserConfig holds bash parser settings.
type ParserConfig struct {
	Dialect        string `toml:"dialect"`
	ResolveAliases bool   `toml:"resolve_aliases"`
}

// ClassifierConfig holds classifier behaviour settings.
type ClassifierConfig struct {
	DefaultDecision       string `toml:"default_decision"`
	UnresolvableExpansion string `toml:"unresolvable_expansion"`
	MaxASTDepth           int    `toml:"max_ast_depth"`
	MaxCommandLength      int    `toml:"max_command_length"`
}

// RulesConfig holds the three priority tiers of rules.
type RulesConfig struct {
	Red    []Rule `toml:"red"`
	Green  []Rule `toml:"green"`
	Yellow []Rule `toml:"yellow"`
}

// Rule describes a single classification rule.
type Rule struct {
	Command     string         `toml:"command"`
	Commands    []string       `toml:"commands"`
	Subcommands []string       `toml:"subcommands"`
	Flags       []string       `toml:"flags"`
	Args        []string       `toml:"args"`
	Pattern     string         `toml:"pattern"`
	Scope       string         `toml:"scope"`
	Context     string         `toml:"context"`
	Resolve     *ResolveConfig `toml:"resolve"`
	LLMReview   *bool          `toml:"llm_review"`
	Reason      string         `toml:"reason"`
}

// ResolveConfig specifies a contextual trust resolver.
type ResolveConfig struct {
	Resolver string `toml:"resolver"`
	Scope    string `toml:"scope"`
}

// LLMConfig holds LLM reviewer settings.
type LLMConfig struct {
	Provider                   string   `toml:"provider"`
	Model                      string   `toml:"model"`
	APIKey                     string   `toml:"api_key"`
	MaxTokens                  int      `toml:"max_tokens"`
	Temperature                float64  `toml:"temperature"`
	AllowFileRetrieval         bool     `toml:"allow_file_retrieval"`
	MaxFileSize                int      `toml:"max_file_size"`
	AllowedPaths               []string `toml:"allowed_paths"`
	DeniedPaths                []string `toml:"denied_paths"`
	SystemPrompt               string   `toml:"system_prompt"`
	MaxResponseReasoningLength int      `toml:"max_response_reasoning_length"`
}

// ScrubbingConfig holds secret-scrubbing settings.
type ScrubbingConfig struct {
	ExtraPatterns []string `toml:"extra_patterns"`
}

// CorpusConfig holds precedent corpus settings.
type CorpusConfig struct {
	Enabled                  bool    `toml:"enabled"`
	Path                     string  `toml:"path"`
	MaxPrecedents            int     `toml:"max_precedents"`
	MinSimilarity            float64 `toml:"min_similarity"`
	ExactHitMode             string  `toml:"exact_hit_mode"`
	MaxAge                   string  `toml:"max_age"`
	MaxEntries               int     `toml:"max_entries"`
	PruneInterval            string  `toml:"prune_interval"`
	StoreDecisions           string  `toml:"store_decisions"`
	StoreReasoning           bool    `toml:"store_reasoning"`
	StoreRawCommand          bool    `toml:"store_raw_command"`
	StoreUserApprovals       bool    `toml:"store_user_approvals"`
	MaxPrecedentsPerDecision int     `toml:"max_precedents_per_decision"`
}

// TelemetryConfig holds OpenTelemetry export settings.
type TelemetryConfig struct {
	Enabled        bool   `toml:"enabled"`
	Endpoint       string `toml:"endpoint"`
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	Protocol       string `toml:"protocol"`
	ExportLogs     bool   `toml:"export_logs"`
	ExportMetrics  bool   `toml:"export_metrics"`
	ExportTraces   bool   `toml:"export_traces"`
	ServiceName    string `toml:"service_name"`
}

// LogConfig holds local logging settings.
type LogConfig struct {
	Level       string `toml:"level"`
	Format      string `toml:"format"`
	File        string `toml:"file"`
	LogCommands bool   `toml:"log_commands"`
	LogLLM      bool   `toml:"log_llm"`
}

// Load reads the TOML config at path, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}

	applyDefaults(&cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// applyDefaults fills in sensible defaults for optional fields.
func applyDefaults(cfg *Config) {
	if cfg.LLM.Provider == "" {
		cfg.LLM.Provider = "anthropic"
	}
	if cfg.Parser.Dialect == "" {
		cfg.Parser.Dialect = "bash"
	}
	if cfg.Classifier.DefaultDecision == "" {
		cfg.Classifier.DefaultDecision = "yellow"
	}
	if cfg.Classifier.UnresolvableExpansion == "" {
		cfg.Classifier.UnresolvableExpansion = "yellow"
	}
	if cfg.Classifier.MaxASTDepth == 0 {
		cfg.Classifier.MaxASTDepth = 64
	}
	if cfg.Classifier.MaxCommandLength == 0 {
		cfg.Classifier.MaxCommandLength = 65536
	}
}

// Validate checks that required fields have acceptable values.
func (cfg *Config) Validate() error {
	validDecisions := map[string]bool{"red": true, "yellow": true, "green": true}

	if !validDecisions[cfg.Classifier.DefaultDecision] {
		return fmt.Errorf("config: classifier.default_decision must be red, yellow, or green; got %q", cfg.Classifier.DefaultDecision)
	}

	if cfg.Classifier.UnresolvableExpansion != "" && !validDecisions[cfg.Classifier.UnresolvableExpansion] {
		return fmt.Errorf("config: classifier.unresolvable_expansion must be red, yellow, or green; got %q", cfg.Classifier.UnresolvableExpansion)
	}

	validExactHitModes := map[string]bool{"": true, "precedent": true, "auto_decide": true}
	if !validExactHitModes[cfg.Corpus.ExactHitMode] {
		return fmt.Errorf("config: corpus.exact_hit_mode must be precedent or auto_decide; got %q", cfg.Corpus.ExactHitMode)
	}

	if cfg.Classifier.MaxASTDepth < 0 {
		return fmt.Errorf("config: classifier.max_ast_depth must be non-negative; got %d", cfg.Classifier.MaxASTDepth)
	}

	if cfg.Classifier.MaxCommandLength < 0 {
		return fmt.Errorf("config: classifier.max_command_length must be non-negative; got %d", cfg.Classifier.MaxCommandLength)
	}

	if cfg.Corpus.MinSimilarity < 0 || cfg.Corpus.MinSimilarity > 1 {
		return fmt.Errorf("config: corpus.min_similarity must be between 0.0 and 1.0; got %f", cfg.Corpus.MinSimilarity)
	}

	validDialects := map[string]bool{"bash": true, "posix": true, "mksh": true}
	if !validDialects[cfg.Parser.Dialect] {
		return fmt.Errorf("config: parser.dialect must be bash, posix, or mksh; got %q", cfg.Parser.Dialect)
	}

	// Validate regex patterns in rules compile.
	for i, rule := range cfg.Rules.Red {
		if err := validateRulePattern(rule.Pattern); err != nil {
			return fmt.Errorf("config: rules.red[%d]: %w", i, err)
		}
	}
	for i, rule := range cfg.Rules.Green {
		if err := validateRulePattern(rule.Pattern); err != nil {
			return fmt.Errorf("config: rules.green[%d]: %w", i, err)
		}
	}
	for i, rule := range cfg.Rules.Yellow {
		if err := validateRulePattern(rule.Pattern); err != nil {
			return fmt.Errorf("config: rules.yellow[%d]: %w", i, err)
		}
	}

	return nil
}
