package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/limbic-systems/stargate/internal/types"
)

// makeCmd is a convenience constructor for CommandInfo values in tests.
func makeCmd(name, subcommand string, flags []string, ctx types.CommandContext) types.CommandInfo {
	return types.CommandInfo{
		Name:       name,
		Subcommand: subcommand,
		Flags:      flags,
		Args:       nil,
		Context:    ctx,
	}
}

// topLevel returns a zero-value CommandContext (top_level).
func topLevel() types.CommandContext { return types.CommandContext{} }

// pipeCtx returns a CommandContext for the given pipeline position.
func pipeCtx(pos int) types.CommandContext {
	return types.CommandContext{PipelinePosition: pos}
}

// TestComputeSignature_Deterministic verifies that the same command list always
// produces the same signature and hash.
func TestComputeSignature_Deterministic(t *testing.T) {
	cmds := []types.CommandInfo{
		makeCmd("git", "status", []string{"-s"}, topLevel()),
	}

	sig1, hash1 := ComputeSignature(cmds)
	sig2, hash2 := ComputeSignature(cmds)

	if sig1 != sig2 {
		t.Errorf("non-deterministic signature: %q vs %q", sig1, sig2)
	}
	if hash1 != hash2 {
		t.Errorf("non-deterministic hash: %q vs %q", hash1, hash2)
	}
}

// TestComputeSignature_ArgsIgnored verifies that commands differing only in
// their positional arguments produce the same signature.
func TestComputeSignature_ArgsIgnored(t *testing.T) {
	cmd1 := types.CommandInfo{
		Name:       "grep",
		Subcommand: "",
		Flags:      []string{"-r"},
		Args:       []string{"pattern1", "/path/a"},
		Context:    topLevel(),
	}
	cmd2 := types.CommandInfo{
		Name:       "grep",
		Subcommand: "",
		Flags:      []string{"-r"},
		Args:       []string{"completely_different_pattern", "/path/b"},
		Context:    topLevel(),
	}

	sig1, hash1 := ComputeSignature([]types.CommandInfo{cmd1})
	sig2, hash2 := ComputeSignature([]types.CommandInfo{cmd2})

	if sig1 != sig2 {
		t.Errorf("different args changed signature: %q vs %q", sig1, sig2)
	}
	if hash1 != hash2 {
		t.Errorf("different args changed hash: %q vs %q", hash1, hash2)
	}
}

// TestComputeSignature_DifferentFlags verifies that commands with different
// flags produce different signatures.
func TestComputeSignature_DifferentFlags(t *testing.T) {
	cmd1 := makeCmd("rm", "", []string{"-rf"}, topLevel())
	cmd2 := makeCmd("rm", "", []string{"-r"}, topLevel())

	sig1, _ := ComputeSignature([]types.CommandInfo{cmd1})
	sig2, _ := ComputeSignature([]types.CommandInfo{cmd2})

	if sig1 == sig2 {
		t.Errorf("different flags produced same signature: %q", sig1)
	}
}

// TestComputeSignature_PipelineOrderPreserved verifies that pipeline position
// is reflected in the ordering of tuples in the signature.
func TestComputeSignature_PipelineOrderPreserved(t *testing.T) {
	// ps aux | grep foo
	cmds := []types.CommandInfo{
		makeCmd("ps", "", []string{"aux"}, pipeCtx(1)),
		makeCmd("grep", "", []string{}, pipeCtx(2)),
	}

	sig, hash := ComputeSignature(cmds)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	// Reversed order (grep at pos 1, ps at pos 2) should produce a different signature.
	reversed := []types.CommandInfo{
		makeCmd("grep", "", []string{}, pipeCtx(1)),
		makeCmd("ps", "", []string{"aux"}, pipeCtx(2)),
	}
	sigRev, hashRev := ComputeSignature(reversed)

	if sig == sigRev {
		t.Errorf("reversed pipeline order produced same signature: %q", sig)
	}
	if hash == hashRev {
		t.Errorf("reversed pipeline order produced same hash")
	}
}

// TestComputeSignature_Empty verifies that an empty command list produces a
// consistent, non-empty JSON array signature ("[]").
func TestComputeSignature_Empty(t *testing.T) {
	sig1, hash1 := ComputeSignature(nil)
	sig2, hash2 := ComputeSignature([]types.CommandInfo{})

	if sig1 != "[]" {
		t.Errorf("nil cmds: expected signature %q, got %q", "[]", sig1)
	}
	if sig2 != "[]" {
		t.Errorf("empty cmds: expected signature %q, got %q", "[]", sig2)
	}
	if sig1 != sig2 {
		t.Errorf("nil and empty slices produced different signatures: %q vs %q", sig1, sig2)
	}

	expectedHash := hex.EncodeToString(func() []byte {
		s := sha256.Sum256([]byte("[]"))
		return s[:]
	}())
	if hash1 != expectedHash {
		t.Errorf("unexpected hash for empty list: got %q, want %q", hash1, expectedHash)
	}
	if hash1 != hash2 {
		t.Errorf("nil and empty slices produced different hashes: %q vs %q", hash1, hash2)
	}
}

// TestComputeSignature_FlagSortingDeterministic verifies that flags in
// different orders produce the same signature.
func TestComputeSignature_FlagSortingDeterministic(t *testing.T) {
	cmd1 := makeCmd("ls", "", []string{"-b", "-a"}, topLevel())
	cmd2 := makeCmd("ls", "", []string{"-a", "-b"}, topLevel())

	sig1, hash1 := ComputeSignature([]types.CommandInfo{cmd1})
	sig2, hash2 := ComputeSignature([]types.CommandInfo{cmd2})

	if sig1 != sig2 {
		t.Errorf("flag order changed signature: %q vs %q", sig1, sig2)
	}
	if hash1 != hash2 {
		t.Errorf("flag order changed hash: %q vs %q", hash1, hash2)
	}
}

// TestComputeSignature_HashMatchesSignature verifies that the returned hash is
// always the SHA-256 of the returned signature string.
func TestComputeSignature_HashMatchesSignature(t *testing.T) {
	cmds := []types.CommandInfo{
		makeCmd("git", "commit", []string{"-m"}, topLevel()),
	}
	sig, hash := ComputeSignature(cmds)

	sum := sha256.Sum256([]byte(sig))
	expected := hex.EncodeToString(sum[:])

	if hash != expected {
		t.Errorf("hash mismatch: got %q, want %q (signature=%q)", hash, expected, sig)
	}
}

// TestCommandNames_DeduplicatesAndSorts verifies that CommandNames returns a
// sorted, deduplicated list of command names.
func TestCommandNames_DeduplicatesAndSorts(t *testing.T) {
	cmds := []types.CommandInfo{
		makeCmd("grep", "", nil, topLevel()),
		makeCmd("find", "", nil, topLevel()),
		makeCmd("grep", "", nil, pipeCtx(2)), // duplicate
		makeCmd("awk", "", nil, topLevel()),
	}

	names := CommandNames(cmds)

	expected := []string{"awk", "find", "grep"}
	if len(names) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, names)
	}
	for i, want := range expected {
		if names[i] != want {
			t.Errorf("names[%d]: got %q, want %q", i, names[i], want)
		}
	}
}

// TestCommandNames_Empty verifies that an empty command list returns an empty
// (not nil) slice.
func TestCommandNames_Empty(t *testing.T) {
	names := CommandNames(nil)
	if names == nil {
		t.Error("expected non-nil slice for nil input")
	}
	if len(names) != 0 {
		t.Errorf("expected empty slice, got %v", names)
	}
}

// TestContextLabel verifies that each CommandContext field maps to the correct
// label string, and that the priority order matches the classifier.
func TestContextLabel(t *testing.T) {
	tests := []struct {
		name string
		ctx  types.CommandContext
		want string
	}{
		{
			name: "InSubstitution takes priority over all others",
			ctx: types.CommandContext{
				InSubstitution:   true,
				InCondition:      true,
				InFunction:       "myfunc",
				SubshellDepth:    1,
				PipelinePosition: 1,
			},
			want: "substitution",
		},
		{
			name: "InCondition",
			ctx:  types.CommandContext{InCondition: true},
			want: "condition",
		},
		{
			name: "InFunction",
			ctx:  types.CommandContext{InFunction: "deploy"},
			want: "function",
		},
		{
			name: "SubshellDepth > 0",
			ctx:  types.CommandContext{SubshellDepth: 2},
			want: "subshell",
		},
		{
			name: "PipelinePosition == 1",
			ctx:  types.CommandContext{PipelinePosition: 1},
			want: "pipeline_source",
		},
		{
			name: "PipelinePosition == 2",
			ctx:  types.CommandContext{PipelinePosition: 2},
			want: "pipeline_sink",
		},
		{
			name: "PipelinePosition >= 3",
			ctx:  types.CommandContext{PipelinePosition: 5},
			want: "pipeline_sink",
		},
		{
			name: "default (top-level)",
			ctx:  types.CommandContext{},
			want: "top_level",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := contextLabel(tc.ctx)
			if got != tc.want {
				t.Errorf("contextLabel(%+v) = %q, want %q", tc.ctx, got, tc.want)
			}
		})
	}
}

// TestComputeSignature_ContextInSignature verifies that the context field is
// included in the signature (so commands in different contexts have different
// signatures even if name/flags are the same).
func TestComputeSignature_ContextInSignature(t *testing.T) {
	cmd1 := makeCmd("echo", "", []string{}, topLevel())
	cmd2 := makeCmd("echo", "", []string{}, types.CommandContext{InSubstitution: true})

	sig1, _ := ComputeSignature([]types.CommandInfo{cmd1})
	sig2, _ := ComputeSignature([]types.CommandInfo{cmd2})

	if sig1 == sig2 {
		t.Errorf("different contexts produced same signature: %q", sig1)
	}
}
