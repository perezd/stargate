package scopes_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/limbic-systems/stargate/internal/scopes"
	"github.com/limbic-systems/stargate/internal/types"
)

// helper builds a CommandInfo with the given flags and args.
func ghCmd(flags []string, args []string) types.CommandInfo {
	return types.CommandInfo{
		Name:  "gh",
		Flags: flags,
		Args:  args,
	}
}

func ghCmdWithRaw(flags, args, rawArgs []string) types.CommandInfo {
	return types.CommandInfo{
		Name:    "gh",
		Flags:   flags,
		Args:    args,
		RawArgs: rawArgs,
	}
}

// --- Step 1: --repo= / -R= flag extraction ---

func TestRepoFlagEquals(t *testing.T) {
	tests := []struct {
		name   string
		cmd    types.CommandInfo
		want   string
		wantOK bool
	}{
		{
			name:   "repo equals form",
			cmd:    ghCmd([]string{"--repo=derek/stargate"}, []string{"pr", "list"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "R equals form",
			cmd:    ghCmd([]string{"-R=derek/stargate"}, []string{"issue", "create"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "repo flag without equals (space form, value consumed by walker)",
			cmd:    ghCmd([]string{"--repo"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "R flag without equals (space form, value consumed by walker)",
			cmd:    ghCmd([]string{"-R"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "repo equals invalid value",
			cmd:    ghCmd([]string{"--repo=invalid"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "repo equals with extra slashes",
			cmd:    ghCmd([]string{"--repo=a/b/c"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, tt.cmd, t.TempDir())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("owner = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Step 2: gh api path extraction ---

func TestAPIPathExtraction(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		want   string
		wantOK bool
	}{
		{
			name:   "repos path",
			args:   []string{"api", "repos/derek/stargate/pulls"},
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "repos path with leading slash",
			args:   []string{"api", "/repos/derek/stargate/pulls"},
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "traversal attack",
			args:   []string{"api", "repos/derek/../evil/repo"},
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty segment",
			args:   []string{"api", "repos/derek//repo"},
			want:   "",
			wantOK: false,
		},
		{
			name:   "url-encoded owner",
			args:   []string{"api", "repos/de%72ek/stargate/pulls"},
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "no repos path",
			args:   []string{"api", "graphql"},
			want:   "",
			wantOK: false,
		},
		{
			name:   "repos path too short",
			args:   []string{"api", "repos/derek"},
			want:   "",
			wantOK: false,
		},
		{
			name:   "repos with dot segment",
			args:   []string{"api", "repos/./stargate/pulls"},
			want:   "",
			wantOK: false,
		},
		{
			name:   "repos minimal valid",
			args:   []string{"api", "repos/owner/repo"},
			want:   "owner",
			wantOK: true,
		},
		{
			name:   "repos with deeply nested path",
			args:   []string{"api", "repos/org/repo/issues/123/comments"},
			want:   "org",
			wantOK: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := ghCmd(nil, tt.args)
			got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, t.TempDir())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("owner = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Step 3: .git/config inference ---

func writeGitConfig(t *testing.T, dir string, content string) {
	t.Helper()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(content), 0o644); err != nil {
		t.Fatalf("write .git/config: %v", err)
	}
}

func TestGitConfigHTTPS(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[core]
	repositoryformatversion = 0
[remote "origin"]
	url = https://github.com/derek/stargate.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "derek" {
		t.Errorf("owner = %q, want %q", got, "derek")
	}
}

func TestGitConfigHTTPSNoSuffix(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://github.com/myorg/myrepo
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "myorg" {
		t.Errorf("owner = %q, want %q", got, "myorg")
	}
}

func TestGitConfigSSHScp(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = git@github.com:derek/stargate.git
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "derek" {
		t.Errorf("owner = %q, want %q", got, "derek")
	}
}

func TestGitConfigSSHURL(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = ssh://git@github.com:22/derek/stargate.git
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "derek" {
		t.Errorf("owner = %q, want %q", got, "derek")
	}
}

func TestGitConfigNoFile(t *testing.T) {
	dir := t.TempDir()

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	_, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected unresolvable when no .git/config exists")
	}
}

func TestGitConfigNonGitHub(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://gitlab.com/derek/stargate.git
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	_, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected unresolvable for non-GitHub remote")
	}
}

func TestGitConfigMultipleRemotesOnlyOrigin(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "upstream"]
	url = https://github.com/upstream-org/repo.git
[remote "origin"]
	url = https://github.com/derek/stargate.git
[remote "fork"]
	url = https://github.com/someone/stargate.git
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "derek" {
		t.Errorf("owner = %q, want %q (should use origin, not upstream)", got, "derek")
	}
}

// --- Fully unresolvable ---

func TestUnresolvable(t *testing.T) {
	dir := t.TempDir()

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	_, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected unresolvable with no flags, no API path, and no .git/config")
	}
}

// --- Context cancellation ---

func TestContextCancellation(t *testing.T) {
	dir := t.TempDir()
	// Write a git config so we'd normally resolve.
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://github.com/derek/stargate.git
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cmd := ghCmd(nil, []string{"pr", "list"})
	_, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if ok {
		t.Error("expected unresolvable with cancelled context")
	}
}

// --- Priority: flag > API path > git config ---

func TestPriorityFlagOverAPIPath(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://github.com/git-owner/repo.git
`)

	ctx := context.Background()
	cmd := ghCmd(
		[]string{"--repo=flag-owner/repo"},
		[]string{"api", "repos/api-owner/repo/pulls"},
	)
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "flag-owner" {
		t.Errorf("owner = %q, want %q (flag should take priority)", got, "flag-owner")
	}
}

func TestPriorityAPIPathOverGitConfig(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://github.com/git-owner/repo.git
`)

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"api", "repos/api-owner/repo/pulls"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if got != "api-owner" {
		t.Errorf("owner = %q, want %q (API path should take priority over git config)", got, "api-owner")
	}
}

// --- Unparseable --repo blocks .git/config fallthrough ---

func TestRepoFlagUnparseableBlocksFallthrough(t *testing.T) {
	dir := t.TempDir()
	writeGitConfig(t, dir, `[remote "origin"]
	url = https://github.com/trusted-org/repo.git
`)

	tests := []struct {
		name string
		cmd  types.CommandInfo
	}{
		{
			name: "variable expansion --repo $REPO",
			cmd:  ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "$REPO", "pr", "list"}),
		},
		{
			name: "empty --repo value",
			cmd:  ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "", "pr", "list"}),
		},
		{
			name: "--repo with invalid format",
			cmd:  ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "noslash", "pr", "list"}),
		},
		{
			name: "equals-form --repo=$REPO (dynamic value)",
			cmd:  ghCmdWithRaw([]string{"--repo=$REPO"}, []string{"pr", "list"}, []string{"--repo=$REPO", "pr", "list"}),
		},
		{
			name: "equals-form -R=$REPO (dynamic value)",
			cmd:  ghCmdWithRaw([]string{"-R=$REPO"}, []string{"pr", "list"}, []string{"-R=$REPO", "pr", "list"}),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, tt.cmd, dir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok {
				t.Errorf("expected unresolvable, but got owner=%q — .git/config fallthrough should be blocked", got)
			}
		})
	}
}

// --- Resolver registry ---

func TestDefaultResolverRegistry(t *testing.T) {
	rr := scopes.DefaultResolverRegistry()

	if _, ok := rr.Get("github_repo_owner"); !ok {
		t.Error("expected github_repo_owner resolver to be registered")
	}
	if _, ok := rr.Get("url_domain"); !ok {
		t.Error("expected url_domain resolver to be registered")
	}
	if _, ok := rr.Get("nonexistent"); ok {
		t.Error("expected nonexistent resolver to not be registered")
	}
}

func TestResolverRegistryOverwrite(t *testing.T) {
	rr := scopes.NewResolverRegistry()
	called := false
	rr.Register("test", func(_ context.Context, _ types.CommandInfo, _ string) (string, bool, error) {
		called = true
		return "v1", true, nil
	})
	rr.Register("test", func(_ context.Context, _ types.CommandInfo, _ string) (string, bool, error) {
		return "v2", true, nil
	})

	fn, ok := rr.Get("test")
	if !ok {
		t.Fatal("expected resolver to exist")
	}
	val, _, _ := fn(context.Background(), types.CommandInfo{}, "")
	if val != "v2" {
		t.Errorf("got %q, want %q (second registration should overwrite)", val, "v2")
	}
	if called {
		t.Error("first resolver should not have been called")
	}
}

// --- Git worktree support ---

func TestGitWorktreeResolvesOwner(t *testing.T) {
	// Create a main repo with .git/config.
	mainRepo := t.TempDir()
	writeGitConfig(t, mainRepo, `[remote "origin"]
	url = https://github.com/limbic-systems/codetainer.git
`)

	// The .git dir needs a HEAD file for validation.
	if err := os.WriteFile(filepath.Join(mainRepo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}

	// Create a worktree directory with a .git file pointing to the main repo.
	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "my-worktree")
	if err := os.MkdirAll(worktreeGitDir, 0o755); err != nil {
		t.Fatalf("mkdir worktree gitdir: %v", err)
	}
	// Write the .git file in the worktree (pointer to the worktree gitdir).
	gitFile := filepath.Join(worktree, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: "+worktreeGitDir+"\n"), 0o644); err != nil {
		t.Fatalf("write .git file: %v", err)
	}

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, worktree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed from worktree")
	}
	if got != "limbic-systems" {
		t.Errorf("owner = %q, want %q", got, "limbic-systems")
	}
}

func TestGitWorktreeRelativePath(t *testing.T) {
	// Create a main repo with .git/config.
	mainRepo := t.TempDir()
	writeGitConfig(t, mainRepo, `[remote "origin"]
	url = git@github.com:myorg/myrepo.git
`)

	// The .git dir needs a HEAD file for validation.
	if err := os.WriteFile(filepath.Join(mainRepo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}

	// Create worktree inside the main repo (relative gitdir path).
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "feature")
	if err := os.MkdirAll(worktreeGitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	worktree := filepath.Join(mainRepo, ".worktrees", "feature")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatalf("mkdir worktree: %v", err)
	}
	// Relative gitdir path from worktree to main .git/worktrees/feature.
	relPath, err := filepath.Rel(worktree, worktreeGitDir)
	if err != nil {
		t.Fatalf("rel: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+relPath+"\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"api", "graphql"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, worktree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed from worktree with relative gitdir")
	}
	if got != "myorg" {
		t.Errorf("owner = %q, want %q", got, "myorg")
	}
}

func TestGitSubmoduleResolvesOwnConfig(t *testing.T) {
	// Submodule .git files point to .git/modules/<name>, NOT .git/worktrees/<name>.
	// The resolver must read the submodule's own config, not the parent repo's.
	parentRepo := t.TempDir()
	writeGitConfig(t, parentRepo, `[remote "origin"]
	url = https://github.com/parent-org/parent-repo.git
`)
	if err := os.WriteFile(filepath.Join(parentRepo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}

	// Create submodule gitdir inside parent's .git/modules/.
	submoduleGitDir := filepath.Join(parentRepo, ".git", "modules", "my-submodule")
	if err := os.MkdirAll(submoduleGitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(submoduleGitDir, "config"), []byte("[remote \"origin\"]\n\turl = https://github.com/sub-org/sub-repo.git\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(submoduleGitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}

	// Create submodule directory with .git file pointing to modules gitdir.
	submodule := t.TempDir()
	if err := os.WriteFile(filepath.Join(submodule, ".git"), []byte("gitdir: "+submoduleGitDir+"\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	ctx := context.Background()
	cmd := ghCmd(nil, []string{"pr", "list"})
	got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, cmd, submodule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolution to succeed from submodule")
	}
	if got != "sub-org" {
		t.Errorf("owner = %q, want %q (submodule owner, not parent)", got, "sub-org")
	}
}

// --- Step 4: space-separated --repo/-R flag in RawArgs ---

func TestRepoFlagSpaceForm(t *testing.T) {
	tests := []struct {
		name   string
		cmd    types.CommandInfo
		want   string
		wantOK bool
	}{
		{
			name:   "space-separated --repo",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "derek/stargate", "pr", "list"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "space-separated -R",
			cmd:    ghCmdWithRaw([]string{"-R"}, []string{"issue", "create"}, []string{"-R", "derek/stargate", "issue", "create"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "--repo at end of args (no value follows)",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"pr", "list", "--repo"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "--repo after -- (end-of-options)",
			cmd:    ghCmdWithRaw(nil, []string{"pr", "list"}, []string{"--", "--repo", "derek/stargate", "pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "duplicate --repo same owner",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "derek/stargate", "--repo", "derek/other", "pr", "list"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "duplicate --repo different owners (fail-closed)",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "derek/stargate", "--repo", "evil/repo", "pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "--repo with variable expansion value (blocks fallthrough)",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "$REPO", "pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "--repo with empty value (blocks fallthrough)",
			cmd:    ghCmdWithRaw([]string{"--repo"}, []string{"pr", "list"}, []string{"--repo", "", "pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "no --repo in rawArgs",
			cmd:    ghCmdWithRaw(nil, []string{"pr", "list"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "nil rawArgs",
			cmd:    ghCmd([]string{"--repo"}, []string{"pr", "list"}),
			want:   "",
			wantOK: false,
		},
		{
			name:   "equals-form --repo=owner/repo in rawArgs",
			cmd:    ghCmdWithRaw([]string{"--repo=derek/stargate"}, []string{"pr", "list"}, []string{"--repo=derek/stargate", "pr", "list"}),
			want:   "derek",
			wantOK: true,
		},
		{
			name:   "equals-form -R=owner/repo in rawArgs",
			cmd:    ghCmdWithRaw([]string{"-R=derek/stargate"}, []string{"pr", "list"}, []string{"-R=derek/stargate", "pr", "list"}),
			want:   "derek",
			wantOK: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := scopes.ResolveGitHubRepoOwner(ctx, tt.cmd, t.TempDir())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("owner = %q, want %q", got, tt.want)
			}
		})
	}
}
