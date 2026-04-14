// Package config provides TOML config loading and validation for stargate.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// dayDurationRe matches strict "Nd" day format (e.g., "90d", "7d").
// Precompiled to avoid per-call regex compilation in ParseMaxAge.
var dayDurationRe = regexp.MustCompile(`^[1-9]\d*d$`)

// ParseMaxAge parses a duration string that may use "Nd" day format.
// Returns 0 for empty strings.
func ParseMaxAge(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	// Try standard Go duration first.
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			return 0, fmt.Errorf("invalid max_age %q: must be non-negative", s)
		}
		return d, nil
	}
	// Try strict "Nd" format for days (e.g., "90d", "7d").
	if dayDurationRe.MatchString(s) {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return 0, fmt.Errorf("invalid max_age %q (use Go durations like \"1h\" or day-based like \"90d\")", s)
}

// parseDuration validates that a string is a valid, non-negative Go duration.
// Empty strings are allowed (treated as unset).
func parseDuration(field, value string) error {
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("config: %s: invalid duration %q: %w", field, value, err)
	}
	if d < 0 {
		return fmt.Errorf("config: %s: duration must be non-negative; got %q", field, value)
	}
	return nil
}

// parseDayDuration validates non-negative duration strings that may use "d" suffix for days.
// Delegates to ParseMaxAge for the actual parsing — single source of truth.
func parseDayDuration(field, value string) error {
	if value == "" {
		return nil
	}
	_, err := ParseMaxAge(value)
	if err != nil {
		return fmt.Errorf("config: %s: %w", field, err)
	}
	return nil
}

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
	Version    string                    `toml:"-"` // set at startup, not from TOML
	ServerCWD  string                    `toml:"-"` // resolved server working directory, set at startup
	Server     ServerConfig              `toml:"server"`
	Parser     ParserConfig              `toml:"parser"`
	Classifier ClassifierConfig          `toml:"classifier"`
	Scopes     map[string][]string       `toml:"scopes"`
	Rules      RulesConfig               `toml:"rules"`
	Wrappers   []WrapperConfig           `toml:"wrappers"`
	Commands   []CommandFlagsConfig      `toml:"commands"`
	LLM        LLMConfig                 `toml:"llm"`
	Scrubbing  ScrubbingConfig           `toml:"scrubbing"`
	Corpus     CorpusConfig              `toml:"corpus"`
	Telemetry  TelemetryConfig           `toml:"telemetry"`
	Log        LogConfig                 `toml:"log"`
}

// WrapperConfig defines a prefix command that wraps another command.
// The walker strips these and classifies the inner command.
// Flags maps flag names to the number of arguments they consume (0 = no arg).
type WrapperConfig struct {
	Command string         `toml:"command"`
	Flags   map[string]int `toml:"flags"`
	// NoStrip lists flags that indicate the wrapper is NOT executing a command
	// (e.g., "command -v" is a lookup, not execution). When the first
	// post-wrapper token is one of these flags, the wrapper is not stripped.
	NoStrip []string `toml:"no_strip"`
	// ConsumeEnvAssigns causes the walker to also skip VAR=val tokens that
	// appear before the real command (e.g., env FOO=bar cmd).
	ConsumeEnvAssigns bool `toml:"consume_env_assigns"`
	// ConsumeFirstPositional causes the walker to skip the first non-flag
	// positional argument (e.g., timeout's duration argument).
	ConsumeFirstPositional bool `toml:"consume_first_positional"`
}

// CommandFlagsConfig defines global flags for a command that should be skipped
// when extracting the subcommand. E.g., git -C <path> status — -C and its arg
// are skipped to find "status" as the subcommand.
type CommandFlagsConfig struct {
	Command string         `toml:"command"`
	Flags   map[string]int `toml:"flags"`
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
	MaxTokens                  int      `toml:"max_tokens"`
	Temperature                float64  `toml:"temperature"`
	AllowFileRetrieval         bool     `toml:"allow_file_retrieval"`
	MaxFileSize                int      `toml:"max_file_size"`
	MaxFilesPerRequest         int      `toml:"max_files_per_request"`
	MaxTotalFileBytes          int      `toml:"max_total_file_bytes"`
	MaxCallsPerMinute          *int     `toml:"max_calls_per_minute"`
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
	Enabled                *bool   `toml:"enabled"`
	Path                   string  `toml:"path"`
	MaxPrecedents          int     `toml:"max_precedents"`
	MinSimilarity          float64 `toml:"min_similarity"`
	MaxAge                 string  `toml:"max_age"`
	MaxEntries             *int    `toml:"max_entries"`
	PruneInterval          string  `toml:"prune_interval"`
	MaxWritesPerMinute     int     `toml:"max_writes_per_minute"`
	StoreDecisions         string  `toml:"store_decisions"`
	StoreReasoning         *bool   `toml:"store_reasoning"`
	MaxReasoningLength     int     `toml:"max_reasoning_length"`
	StoreRawCommand        *bool   `toml:"store_raw_command"`
	StoreUserApprovals     *bool   `toml:"store_user_approvals"`
	MaxPrecedentsPerPolarity int   `toml:"max_precedents_per_polarity"`
	CommandCacheEnabled    *bool   `toml:"command_cache_enabled"`
	CommandCacheTTL        string  `toml:"command_cache_ttl"`
	CommandCacheMaxEntries int     `toml:"command_cache_max_entries"`
}

// corpusEnabled returns whether the corpus is enabled (defaults to true).
func (c CorpusConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// IsStoreReasoning returns whether reasoning should be stored (defaults to true).
func (c CorpusConfig) IsStoreReasoning() bool {
	if c.StoreReasoning == nil {
		return true
	}
	return *c.StoreReasoning
}

// IsStoreRawCommand returns whether raw commands should be stored (defaults to true).
func (c CorpusConfig) IsStoreRawCommand() bool {
	if c.StoreRawCommand == nil {
		return true
	}
	return *c.StoreRawCommand
}

// IsStoreUserApprovals returns whether user approvals should be stored (defaults to true).
func (c CorpusConfig) IsStoreUserApprovals() bool {
	if c.StoreUserApprovals == nil {
		return true
	}
	return *c.StoreUserApprovals
}

// IsCommandCacheEnabled returns whether the command cache is enabled (defaults to true).
func (c CorpusConfig) IsCommandCacheEnabled() bool {
	if c.CommandCacheEnabled == nil {
		return true
	}
	return *c.CommandCacheEnabled
}

// GetMaxEntries returns the max entries limit. nil (not set) defaults to 10000.
// 0 means unlimited (per spec: "Set to 0 for unlimited").
func (c CorpusConfig) GetMaxEntries() int {
	if c.MaxEntries == nil {
		return 10000
	}
	return *c.MaxEntries
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

	// Capture the server's working directory (symlink-resolved) so all
	// consumers of Config.ServerCWD can trust it's the canonical path.
	// Done in Load so it's set exactly once at startup.
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("config: determine working directory: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = resolved
	}
	cfg.ServerCWD = cwd

	return &cfg, nil
}

// applyDefaults fills in sensible defaults for optional fields.
func applyDefaults(cfg *Config) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "127.0.0.1:9099"
	}
	if cfg.Server.Timeout == "" {
		cfg.Server.Timeout = "10s"
	}
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
	if cfg.LLM.MaxFilesPerRequest == 0 {
		cfg.LLM.MaxFilesPerRequest = 3
	}
	if cfg.LLM.MaxTotalFileBytes == 0 {
		cfg.LLM.MaxTotalFileBytes = 131072 // 128KB
	}
	if cfg.LLM.MaxCallsPerMinute == nil {
		defaultRate := 30
		cfg.LLM.MaxCallsPerMinute = &defaultRate
	}
	if cfg.Corpus.Path == "" {
		cfg.Corpus.Path = "~/.local/share/stargate/precedents.db"
	}
	// MaxPrecedents: 0 means "use default" (5). To disable precedent injection,
	// set corpus.enabled = false instead of max_precedents = 0.
	if cfg.Corpus.MaxPrecedents == 0 {
		cfg.Corpus.MaxPrecedents = 5
	}
	// MinSimilarity: 0 means "use default" (0.7). To disable similarity
	// filtering, set corpus.enabled = false instead of min_similarity = 0.
	if cfg.Corpus.MinSimilarity == 0 {
		cfg.Corpus.MinSimilarity = 0.7
	}
	if cfg.Corpus.MaxAge == "" {
		cfg.Corpus.MaxAge = "90d"
	}
	// MaxEntries: nil means "use default" (10000). Explicit 0 means unlimited.
	// No default needed — GetMaxEntries() handles nil → 10000.
	if cfg.Corpus.PruneInterval == "" {
		cfg.Corpus.PruneInterval = "1h"
	}
	if cfg.Corpus.MaxWritesPerMinute == 0 {
		cfg.Corpus.MaxWritesPerMinute = 10
	}
	if cfg.Corpus.StoreDecisions == "" {
		cfg.Corpus.StoreDecisions = "all"
	}
	if cfg.Corpus.MaxReasoningLength == 0 {
		cfg.Corpus.MaxReasoningLength = 1000
	}
	if cfg.Corpus.MaxPrecedentsPerPolarity == 0 {
		cfg.Corpus.MaxPrecedentsPerPolarity = 3
	}
	if cfg.Wrappers == nil {
		cfg.Wrappers = DefaultWrappers()
	}
	if cfg.Commands == nil {
		cfg.Commands = DefaultCommandFlags()
	}
	if cfg.Corpus.CommandCacheTTL == "" {
		cfg.Corpus.CommandCacheTTL = "1h"
	}
	if cfg.Corpus.CommandCacheMaxEntries == 0 {
		cfg.Corpus.CommandCacheMaxEntries = 10000
	}
}

// DefaultWrappers returns built-in wrapper command definitions.
// Operators can override these entirely by defining [[wrappers]] in their config.
func DefaultWrappers() []WrapperConfig {
	return []WrapperConfig{
		{
			Command: "sudo",
			Flags: map[string]int{
				"-u": 1, "-g": 1, "-c": 1, "-D": 1,
				"-r": 1, "-t": 1, "-T": 1, "-U": 1,
				"-h": 0, "-i": 0, "-s": 0, "-l": 0, "-v": 0,
				"-k": 0, "-K": 0, "-n": 0, "-b": 0,
				"-e": 0, "-A": 0, "-S": 0, "-H": 0, "-P": 0,
			},
		},
		{Command: "doas", Flags: map[string]int{"-u": 1, "-s": 0, "-n": 0}},
		{
			Command:           "env",
			Flags:             map[string]int{"-i": 0, "-u": 1, "-S": 1},
			ConsumeEnvAssigns: true,
		},
		{Command: "nice", Flags: map[string]int{"-n": 1}},
		{
			Command:                "timeout",
			Flags:                  map[string]int{"-k": 1, "--kill-after": 1, "-s": 1, "--signal": 1},
			ConsumeFirstPositional: true,
		},
		{
			Command: "watch",
			Flags:   map[string]int{"-n": 1, "--interval": 1, "-d": 0, "--differences": 0},
		},
		{
			Command: "strace",
			Flags: map[string]int{
				"-e": 1, "-o": 1, "-p": 1, "-s": 1, "-P": 1,
				"-I": 1, "-b": 1, "-a": 1, "-X": 1,
			},
		},
		{Command: "nohup"},
		{Command: "time", Flags: map[string]int{"-p": 0}},
		{
			Command: "command",
			Flags:   map[string]int{"-p": 0},
			NoStrip: []string{"-v", "-V"},
		},
		{Command: "builtin"},
	}
}

// DefaultCommandFlags returns built-in global flag definitions for subcommand extraction.
func DefaultCommandFlags() []CommandFlagsConfig {
	return []CommandFlagsConfig{
		{
			Command: "git",
			Flags: map[string]int{
				"-C": 1, "--git-dir": 1, "--work-tree": 1,
				"--no-pager": 0, "--bare": 0, "--no-replace-objects": 0,
			},
		},
		{
			Command: "docker",
			Flags: map[string]int{
				"--context": 1, "-c": 1, "--host": 1, "-H": 1,
				"--log-level": 1, "-l": 1, "--tls": 0, "--tlsverify": 0,
				"--config": 1, "-D": 0, "--debug": 0,
			},
		},
		{Command: "gh", Flags: map[string]int{"--repo": 1, "-R": 1}},
		{
			Command: "kubectl",
			Flags: map[string]int{
				"--context": 1, "--namespace": 1, "-n": 1,
				"--cluster": 1, "--user": 1, "--kubeconfig": 1,
				"-s": 1, "--server": 1,
			},
		},
	}
}

// Validate checks that required fields have acceptable values.
// This is the authority — if Validate passes, the config is safe to use.
func (cfg *Config) Validate() error {
	// --- Server ---
	if cfg.Server.Listen == "" {
		return fmt.Errorf("config: server.listen is required")
	}
	host, port, err := net.SplitHostPort(cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("config: server.listen is not a valid host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("config: server.listen must bind to a loopback IP (127.0.0.0/8 or [::1]); got %q", cfg.Server.Listen)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 0 || portNum > 65535 {
		return fmt.Errorf("config: server.listen port must be 0-65535; got %q", port)
	}
	if err := parseDuration("server.timeout", cfg.Server.Timeout); err != nil {
		return err
	}

	// --- Parser ---
	validDialects := map[string]bool{"bash": true, "posix": true, "mksh": true}
	if !validDialects[cfg.Parser.Dialect] {
		return fmt.Errorf("config: parser.dialect must be bash, posix, or mksh; got %q", cfg.Parser.Dialect)
	}

	// --- Classifier ---
	validDecisions := map[string]bool{"red": true, "yellow": true, "green": true}
	if !validDecisions[cfg.Classifier.DefaultDecision] {
		return fmt.Errorf("config: classifier.default_decision must be red, yellow, or green; got %q", cfg.Classifier.DefaultDecision)
	}
	if cfg.Classifier.UnresolvableExpansion != "" && !validDecisions[cfg.Classifier.UnresolvableExpansion] {
		return fmt.Errorf("config: classifier.unresolvable_expansion must be red, yellow, or green; got %q", cfg.Classifier.UnresolvableExpansion)
	}
	if cfg.Classifier.MaxASTDepth < 0 {
		return fmt.Errorf("config: classifier.max_ast_depth must be non-negative; got %d", cfg.Classifier.MaxASTDepth)
	}
	if cfg.Classifier.MaxCommandLength < 0 {
		return fmt.Errorf("config: classifier.max_command_length must be non-negative; got %d", cfg.Classifier.MaxCommandLength)
	}

	// --- LLM ---
	if cfg.LLM.MaxTokens < 0 {
		return fmt.Errorf("config: llm.max_tokens must be non-negative; got %d", cfg.LLM.MaxTokens)
	}
	if cfg.LLM.MaxFileSize < 0 {
		return fmt.Errorf("config: llm.max_file_size must be non-negative; got %d", cfg.LLM.MaxFileSize)
	}
	if cfg.LLM.Temperature < 0 || cfg.LLM.Temperature > 2 {
		return fmt.Errorf("config: llm.temperature must be between 0.0 and 2.0; got %f", cfg.LLM.Temperature)
	}
	if cfg.LLM.MaxResponseReasoningLength < 0 {
		return fmt.Errorf("config: llm.max_response_reasoning_length must be non-negative; got %d", cfg.LLM.MaxResponseReasoningLength)
	}
	if cfg.LLM.MaxFilesPerRequest < 0 {
		return fmt.Errorf("config: llm.max_files_per_request must be non-negative; got %d", cfg.LLM.MaxFilesPerRequest)
	}
	if cfg.LLM.MaxTotalFileBytes < 0 {
		return fmt.Errorf("config: llm.max_total_file_bytes must be non-negative; got %d", cfg.LLM.MaxTotalFileBytes)
	}
	if cfg.LLM.MaxCallsPerMinute != nil && *cfg.LLM.MaxCallsPerMinute < 0 {
		return fmt.Errorf("config: llm.max_calls_per_minute must be non-negative; got %d", *cfg.LLM.MaxCallsPerMinute)
	}

	// --- Corpus ---
	if cfg.Corpus.MinSimilarity < 0 || cfg.Corpus.MinSimilarity > 1 {
		return fmt.Errorf("config: corpus.min_similarity must be between 0.0 and 1.0; got %f", cfg.Corpus.MinSimilarity)
	}
	if cfg.Corpus.MaxPrecedents < 0 {
		return fmt.Errorf("config: corpus.max_precedents must be non-negative; got %d", cfg.Corpus.MaxPrecedents)
	}
	if cfg.Corpus.MaxEntries != nil && *cfg.Corpus.MaxEntries < 0 {
		return fmt.Errorf("config: corpus.max_entries must be non-negative; got %d", *cfg.Corpus.MaxEntries)
	}
	if cfg.Corpus.MaxPrecedentsPerPolarity < 0 {
		return fmt.Errorf("config: corpus.max_precedents_per_polarity must be non-negative; got %d", cfg.Corpus.MaxPrecedentsPerPolarity)
	}
	if cfg.Corpus.MaxWritesPerMinute < 0 {
		return fmt.Errorf("config: corpus.max_writes_per_minute must be non-negative; got %d", cfg.Corpus.MaxWritesPerMinute)
	}
	if cfg.Corpus.MaxReasoningLength < 0 {
		return fmt.Errorf("config: corpus.max_reasoning_length must be non-negative; got %d", cfg.Corpus.MaxReasoningLength)
	}
	if err := parseDayDuration("corpus.max_age", cfg.Corpus.MaxAge); err != nil {
		return err
	}
	if err := parseDuration("corpus.prune_interval", cfg.Corpus.PruneInterval); err != nil {
		return err
	}
	validStoreDecisions := map[string]bool{"": true, "all": true, "allow_only": true, "deny_only": true}
	if !validStoreDecisions[cfg.Corpus.StoreDecisions] {
		return fmt.Errorf("config: corpus.store_decisions must be all, allow_only, or deny_only; got %q", cfg.Corpus.StoreDecisions)
	}
	if err := parseDuration("corpus.command_cache_ttl", cfg.Corpus.CommandCacheTTL); err != nil {
		return err
	}
	if cfg.Corpus.CommandCacheMaxEntries < 0 {
		return fmt.Errorf("config: corpus.command_cache_max_entries must be non-negative; got %d", cfg.Corpus.CommandCacheMaxEntries)
	}

	// --- Scrubbing: validate extra regex patterns compile ---
	for i, pattern := range cfg.Scrubbing.ExtraPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("config: scrubbing.extra_patterns[%d]: invalid regex %q: %w", i, pattern, err)
		}
	}

	// --- Rules: validate regex patterns compile ---
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

	// --- Wrappers ---
	wrappersSeen := make(map[string]bool)
	for i, w := range cfg.Wrappers {
		if w.Command == "" {
			return fmt.Errorf("config: wrappers[%d]: command must not be empty", i)
		}
		if wrappersSeen[w.Command] {
			return fmt.Errorf("config: wrappers[%d]: duplicate command %q", i, w.Command)
		}
		wrappersSeen[w.Command] = true
		for flag, argc := range w.Flags {
			if argc < 0 {
				return fmt.Errorf("config: wrappers[%d] (%s): flag %q arg count must be non-negative; got %d", i, w.Command, flag, argc)
			}
		}
	}

	// --- Commands (global flags) ---
	commandsSeen := make(map[string]bool)
	for i, c := range cfg.Commands {
		if c.Command == "" {
			return fmt.Errorf("config: commands[%d]: command must not be empty", i)
		}
		if commandsSeen[c.Command] {
			return fmt.Errorf("config: commands[%d]: duplicate command %q", i, c.Command)
		}
		commandsSeen[c.Command] = true
		for flag, argc := range c.Flags {
			if argc < 0 {
				return fmt.Errorf("config: commands[%d] (%s): flag %q arg count must be non-negative; got %d", i, c.Command, flag, argc)
			}
		}
	}

	// --- Telemetry ---
	if cfg.Telemetry.Enabled && cfg.Telemetry.Endpoint == "" {
		return fmt.Errorf("config: telemetry.endpoint is required when telemetry is enabled")
	}
	validTelemetryProtocols := map[string]bool{"": true, "http/protobuf": true, "grpc": true}
	if !validTelemetryProtocols[cfg.Telemetry.Protocol] {
		return fmt.Errorf("config: telemetry.protocol must be http/protobuf or grpc; got %q", cfg.Telemetry.Protocol)
	}

	// --- Log ---
	validLogLevels := map[string]bool{"": true, "debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[cfg.Log.Level] {
		return fmt.Errorf("config: log.level must be debug, info, warn, or error; got %q", cfg.Log.Level)
	}
	validLogFormats := map[string]bool{"": true, "text": true, "json": true}
	if !validLogFormats[cfg.Log.Format] {
		return fmt.Errorf("config: log.format must be text or json; got %q", cfg.Log.Format)
	}

	return nil
}
