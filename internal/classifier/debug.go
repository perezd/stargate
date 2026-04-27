package classifier

import "github.com/limbic-systems/stargate/internal/rules"

// DebugInfo contains diagnostic data populated only for /test (DryRun=true).
type DebugInfo struct {
	ScrubbedCommand    string                 `json:"scrubbed_command"`
	RuleTrace          []rules.RuleTraceEntry `json:"rule_trace"`
	Cache              *CacheDebug            `json:"cache,omitempty"`
	PrecedentsInjected []PrecedentDebug       `json:"precedents_injected,omitempty"`
	RenderedPrompts    *PromptDebug           `json:"rendered_prompts,omitempty"`
	LLMRawResponse     string                 `json:"llm_raw_response,omitempty"`
}

type CacheDebug struct {
	Checked bool             `json:"checked"`
	Hit     bool             `json:"hit"`
	Entry   *CacheEntryDebug `json:"entry,omitempty"`
}

type CacheEntryDebug struct {
	Decision string `json:"decision"`
	Action   string `json:"action"`
}

type PrecedentDebug struct {
	ID           string   `json:"id"`
	Decision     string   `json:"decision"`
	Similarity   float64  `json:"similarity"`
	CommandNames []string `json:"command_names"`
	Flags        []string `json:"flags"`
	AgeSeconds   int64    `json:"age_seconds"`
}

type PromptDebug struct {
	System string `json:"system"`
	User   string `json:"user"`
}
