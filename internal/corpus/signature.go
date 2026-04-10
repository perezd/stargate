// Package corpus implements the precedent corpus for the stargate classifier.
// It provides structural signature computation and storage of command precedents.
package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/limbic-systems/stargate/internal/types"
)

// signatureTuple is a deterministic, argument-agnostic representation of a
// single command invocation. It intentionally omits Args, Redirects, and Env
// so that two invocations that differ only in their arguments (e.g., different
// filenames passed to grep) produce the same signature.
type signatureTuple struct {
	Name       string   `json:"name"`
	Subcommand string   `json:"subcommand"`
	Flags      []string `json:"flags"`
	Context    string   `json:"context"`
}

// ComputeSignature extracts structural tuples from cmds, serializes them as
// canonical JSON, and returns the signature string and its SHA-256 hash.
//
// The signature is argument-agnostic: only Name, Subcommand, sorted Flags, and
// the context label are included. Tuples are ordered by PipelinePosition so
// that pipeline structure is preserved. Commands not in a pipeline are placed
// before those in a pipeline (PipelinePosition == 0 sorts first).
func ComputeSignature(cmds []types.CommandInfo) (signature string, hash string) {
	// Sort a copy by pipeline position to preserve pipeline order while keeping
	// the function side-effect-free on the caller's slice.
	sorted := make([]types.CommandInfo, len(cmds))
	copy(sorted, cmds)
	slices.SortStableFunc(sorted, func(a, b types.CommandInfo) int {
		return a.Context.PipelinePosition - b.Context.PipelinePosition
	})

	tuples := make([]signatureTuple, len(sorted))
	for i, cmd := range sorted {
		flags := make([]string, len(cmd.Flags))
		copy(flags, cmd.Flags)
		slices.Sort(flags)

		tuples[i] = signatureTuple{
			Name:       cmd.Name,
			Subcommand: cmd.Subcommand,
			Flags:      flags,
			Context:    contextLabel(cmd.Context),
		}
	}

	// Use a nil-safe empty array so that an empty command list serializes as
	// "[]" rather than "null".
	if tuples == nil {
		tuples = []signatureTuple{}
	}

	b, err := json.Marshal(tuples)
	if err != nil {
		// json.Marshal on a []signatureTuple (all string fields) cannot fail in
		// practice, but if it somehow does we return a stable sentinel.
		return "[]", hashString("[]")
	}

	sig := string(b)
	return sig, hashString(sig)
}

// CommandNames extracts deduplicated, sorted command names from cmds.
// The returned slice is suitable for storage in the corpus command_names
// JSON array column.
func CommandNames(cmds []types.CommandInfo) []string {
	seen := make(map[string]struct{}, len(cmds))
	for _, cmd := range cmds {
		seen[cmd.Name] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// contextLabel maps a CommandContext to the canonical label used in signatures
// and AST summaries. The ordering of cases matches the classifier's contextLabel
// function exactly so that the two are always consistent.
func contextLabel(ctx types.CommandContext) string {
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

// hashString returns the lowercase hex-encoded SHA-256 digest of s.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
