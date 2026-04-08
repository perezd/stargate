package scopes

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/limbic-systems/stargate/internal/rules"
)

// validGitHubName matches valid GitHub owner and repo names:
// alphanumeric, hyphens, dots, and underscores.
var validGitHubName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ResolveGitHubRepoOwner extracts the GitHub repository owner from a command.
//
// Resolution order (first match wins):
//  1. Explicit --repo=owner/repo or -R=owner/repo flag in CommandInfo.Flags
//  2. GitHub API path in Args (repos/owner/repo/...)
//  3. Inference from .git/config remote "origin" URL
//
// The space-separated form (--repo owner/repo) is consumed by the walker's
// global flag skipping and is not available in CommandInfo. Users of that form
// fall through to .git/config inference.
func ResolveGitHubRepoOwner(ctx context.Context, cmd rules.CommandInfo, cwd string) (string, bool, error) {
	// Step 1: Check flags for --repo=owner/repo or -R=owner/repo.
	if owner, ok := ownerFromRepoFlag(cmd.Flags); ok {
		return owner, true, nil
	}

	// Step 2: Check args for gh api repos/owner/repo/... path.
	if owner, ok := ownerFromAPIPath(cmd.Args); ok {
		return owner, true, nil
	}

	// Step 3: Infer from .git/config.
	owner, ok, err := ownerFromGitConfig(ctx, cwd)
	if err != nil {
		return "", false, fmt.Errorf("github_repo_owner: git config: %w", err)
	}
	if ok {
		return owner, true, nil
	}

	return "", false, nil
}

// ownerFromRepoFlag scans flags for --repo=owner/repo or -R=owner/repo.
func ownerFromRepoFlag(flags []string) (string, bool) {
	for _, f := range flags {
		var value string
		switch {
		case strings.HasPrefix(f, "--repo="):
			value = f[len("--repo="):]
		case strings.HasPrefix(f, "-R="):
			value = f[len("-R="):]
		default:
			continue
		}
		owner, ok := parseOwnerRepo(value)
		if ok {
			return owner, true
		}
	}
	return "", false
}

// ownerFromAPIPath scans positional args for a GitHub API path like
// repos/owner/repo/... and extracts the owner.
func ownerFromAPIPath(args []string) (string, bool) {
	for _, arg := range args {
		// URL-decode first to handle encoded characters.
		decoded, err := url.PathUnescape(arg)
		if err != nil {
			continue
		}

		// Strip leading slash for /repos/... form.
		path := strings.TrimPrefix(decoded, "/")

		if !strings.HasPrefix(path, "repos/") {
			continue
		}

		segments := strings.Split(path, "/")
		// Need at least: repos, owner, repo
		if len(segments) < 3 {
			continue
		}

		// Validate no empty segments or traversal.
		for _, seg := range segments {
			if seg == "" || seg == ".." || seg == "." {
				return "", false
			}
		}

		owner := segments[1]
		repo := segments[2]

		if !validGitHubName.MatchString(owner) || !validGitHubName.MatchString(repo) {
			return "", false
		}

		return owner, true
	}
	return "", false
}

// parseOwnerRepo splits an "owner/repo" string and validates both parts.
func parseOwnerRepo(s string) (string, bool) {
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || owner == "" || repo == "" {
		return "", false
	}
	// Reject if there are additional slashes (e.g., "owner/repo/extra").
	if strings.Contains(repo, "/") {
		return "", false
	}
	if !validGitHubName.MatchString(owner) || !validGitHubName.MatchString(repo) {
		return "", false
	}
	return owner, true
}

// ownerFromGitConfig reads .git/config in cwd and extracts the owner from
// the "origin" remote URL. Only GitHub URLs are supported.
func ownerFromGitConfig(ctx context.Context, cwd string) (string, bool, error) {
	configPath := filepath.Join(cwd, ".git", "config")

	// Check context before file I/O.
	select {
	case <-ctx.Done():
		return "", false, ctx.Err()
	default:
	}

	f, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	defer f.Close()

	remoteURL, ok := parseGitConfigOriginURL(f)
	if !ok {
		return "", false, nil
	}

	owner, ok := ownerFromGitURL(remoteURL)
	if !ok {
		return "", false, nil
	}
	return owner, true, nil
}

// parseGitConfigOriginURL reads an INI-style git config and extracts the URL
// from [remote "origin"].
func parseGitConfigOriginURL(f *os.File) (string, bool) {
	scanner := bufio.NewScanner(f)
	inOrigin := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header.
		if strings.HasPrefix(line, "[") {
			inOrigin = strings.HasPrefix(line, `[remote "origin"]`)
			continue
		}

		if inOrigin {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if strings.TrimSpace(key) == "url" {
				return strings.TrimSpace(value), true
			}
		}
	}

	return "", false
}

// ownerFromGitURL parses a GitHub remote URL and extracts the owner.
// Supported formats:
//   - HTTPS: https://github.com/owner/repo[.git]
//   - SSH scp: git@github.com:owner/repo[.git]
//   - SSH URL: ssh://git@github.com[:port]/owner/repo[.git]
func ownerFromGitURL(rawURL string) (string, bool) {
	// SSH scp-style: git@github.com:owner/repo[.git]
	if strings.HasPrefix(rawURL, "git@github.com:") {
		path := strings.TrimPrefix(rawURL, "git@github.com:")
		return ownerFromGitPath(path)
	}

	// Parse as URL for HTTPS and ssh:// forms.
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}

	// Must be GitHub.
	host := u.Hostname()
	if host != "github.com" {
		return "", false
	}

	return ownerFromGitPath(strings.TrimPrefix(u.Path, "/"))
}

// ownerFromGitPath extracts the owner from a "owner/repo[.git]" path.
func ownerFromGitPath(path string) (string, bool) {
	// Strip trailing .git suffix.
	path = strings.TrimSuffix(path, ".git")

	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}

	owner := parts[0]
	repo := parts[1]
	if !validGitHubName.MatchString(owner) || !validGitHubName.MatchString(repo) {
		return "", false
	}

	return owner, true
}
