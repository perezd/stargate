package scopes

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/limbic-systems/stargate/internal/rules"
)

// rejectedSchemes lists URL schemes that are not network-accessible and must
// be rejected by the url_domain resolver.
var rejectedSchemes = map[string]bool{
	"file": true,
	"data": true,
}

// ResolveURLDomain extracts the domain (host without port) from the first
// URL-like argument in cmd.Args.
//
// Detection order:
//  1. An arg containing "://" is treated as a full URL.
//  2. An arg containing "." and not starting with "-" is treated as a schemeless
//     domain and is prepended with "https://" before parsing.
//
// Rejected schemes (file:, data:, etc.) and args with no URL return unresolvable.
func ResolveURLDomain(_ context.Context, cmd rules.CommandInfo, _ string) (string, bool, error) {
	for _, arg := range cmd.Args {
		raw, ok := extractURLCandidate(arg)
		if !ok {
			continue
		}

		domain, ok := parseURLDomain(raw)
		if !ok {
			// Explicit scheme that we reject → stop and return unresolvable.
			// (If it looked like a URL but failed to parse, keep scanning.)
			if strings.Contains(arg, "://") {
				return "", false, nil
			}
			continue
		}

		return domain, true, nil
	}

	return "", false, nil
}

// extractURLCandidate returns a raw URL string (possibly with https:// prepended)
// and whether the arg looks like a URL candidate.
func extractURLCandidate(arg string) (string, bool) {
	// Full URL: contains a scheme separator.
	if strings.Contains(arg, "://") {
		return arg, true
	}

	// Schemeless candidate: contains a dot, no leading dash (flag), no leading slash (path).
	if strings.Contains(arg, ".") && !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "/") {
		return "https://" + arg, true
	}

	return "", false
}

// parseURLDomain parses a raw URL and returns the host without port.
// Returns ("", false) if the scheme is rejected or the URL is unparseable.
func parseURLDomain(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}

	// Reject non-network schemes.
	if rejectedSchemes[strings.ToLower(u.Scheme)] {
		return "", false
	}

	host := u.Host

	// Strip port using net.SplitHostPort; fall back to the raw host on error
	// (e.g., plain "example.com" without a port is not valid for SplitHostPort).
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// net.SplitHostPort strips brackets from IPv6 literals like [::1].
	// Return the bare address so callers get "::1" rather than "[::1]".

	if host == "" {
		return "", false
	}

	return host, true
}
