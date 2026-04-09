package scopes

import (
	"context"

	"github.com/limbic-systems/stargate/internal/types"
)

// ResolverAdapter wraps *ResolverRegistry to satisfy types.ResolverProvider.
// It bridges the scopes.Resolver signature (types.CommandInfo) to the
// types.ResolverFunc signature, which is identical after the types extraction.
type ResolverAdapter struct {
	rr *ResolverRegistry
}

// NewResolverAdapter wraps a ResolverRegistry so it satisfies types.ResolverProvider.
func NewResolverAdapter(rr *ResolverRegistry) *ResolverAdapter {
	return &ResolverAdapter{rr: rr}
}

// Get implements types.ResolverProvider.
func (a *ResolverAdapter) Get(name string) (types.ResolverFunc, bool) {
	r, ok := a.rr.Get(name)
	if !ok {
		return nil, false
	}
	return func(ctx context.Context, cmd types.CommandInfo, cwd string) (string, bool, error) {
		return r(ctx, cmd, cwd)
	}, true
}
