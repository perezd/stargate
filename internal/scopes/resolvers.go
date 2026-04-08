package scopes

import (
	"context"

	"github.com/limbic-systems/stargate/internal/rules"
)

// Resolver extracts a target value from a command for scope matching.
// Returns the resolved value and whether resolution succeeded.
// Errors are treated as unresolvable (fail-closed) and should be logged by callers.
type Resolver func(ctx context.Context, cmd rules.CommandInfo, cwd string) (value string, ok bool, err error)

// ResolverRegistry maps resolver names to their implementations.
type ResolverRegistry struct {
	resolvers map[string]Resolver
}

// NewResolverRegistry creates an empty resolver registry.
func NewResolverRegistry() *ResolverRegistry {
	return &ResolverRegistry{
		resolvers: make(map[string]Resolver),
	}
}

// Register adds a resolver under the given name. If a resolver with that name
// already exists, it is replaced.
func (r *ResolverRegistry) Register(name string, resolver Resolver) {
	r.resolvers[name] = resolver
}

// Get returns the resolver registered under the given name, or false if none exists.
func (r *ResolverRegistry) Get(name string) (Resolver, bool) {
	fn, ok := r.resolvers[name]
	return fn, ok
}

// DefaultResolverRegistry returns a registry pre-populated with the built-in
// resolvers: github_repo_owner and url_domain.
func DefaultResolverRegistry() *ResolverRegistry {
	rr := NewResolverRegistry()
	rr.Register("github_repo_owner", ResolveGitHubRepoOwner)
	rr.Register("url_domain", ResolveURLDomain)
	return rr
}

