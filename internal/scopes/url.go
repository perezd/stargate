package scopes

import (
	"context"
	"net/url"
	"strings"

	"github.com/limbic-systems/stargate/internal/rules"
)

// acceptedSchemes lists the only URL schemes accepted by the url_domain resolver.
// Everything else (file:, data:, ftp:, ssh:, etc.) is rejected.
var acceptedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// commonFileExts lists common file extensions that indicate a filename rather
// than a domain name. Used to avoid false-positives on args like "output.txt".
var commonFileExts = map[string]bool{
	"txt": true, "log": true, "json": true, "yaml": true, "yml": true,
	"xml": true, "csv": true, "tsv": true, "md": true, "html": true,
	"htm": true, "pdf": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "svg": true, "zip": true, "tar": true, "gz": true,
	"sh": true, "py": true, "go": true, "js": true, "ts": true,
	"conf": true, "cfg": true, "ini": true, "toml": true, "env": true,
	"out": true, "tmp": true, "bak": true,
}

// ResolveURLDomain extracts the domain (host without port) from the first
// URL-like argument in cmd.Args.
//
// Detection order:
//  1. An arg containing "://" is treated as a full URL.
//  2. An arg containing "." and not starting with "-" is treated as a schemeless
//     domain and is prepended with "https://" before parsing.
//
// Only http and https schemes are accepted; all others return unresolvable.
// Schemeless args that look like filenames (e.g., "output.txt") are skipped.
func ResolveURLDomain(_ context.Context, cmd rules.CommandInfo, _ string) (string, bool, error) {
	for _, arg := range cmd.Args {
		raw, ok := extractURLCandidate(arg)
		if !ok {
			continue
		}

		domain, ok := parseURLDomain(raw)
		if !ok {
			// Parse failure for a schemed URL — continue scanning remaining args
			// rather than stopping. (A rejected scheme or unparseable URL should
			// not prevent a later arg from matching.)
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

	// Schemeless candidate: not a flag or obvious path, and the host segment
	// (before the first "/") contains a dot. This prevents "dir/output.txt"
	// from being treated as a domain.
	if !strings.HasPrefix(arg, "-") &&
		!strings.HasPrefix(arg, "/") &&
		!strings.HasPrefix(arg, "./") &&
		!strings.HasPrefix(arg, "../") {
		hostSegment, _, _ := strings.Cut(arg, "/")
		if strings.Contains(hostSegment, ".") {
			// Skip bare filenames with known extensions (no path separator).
			if !strings.Contains(arg, "/") {
				lastDot := strings.LastIndex(arg, ".")
				if lastDot >= 0 {
					ext := strings.ToLower(arg[lastDot+1:])
					if commonFileExts[ext] {
						return "", false
					}
				}
			}
			return "https://" + arg, true
		}
	}

	return "", false
}

// parseURLDomain parses a raw URL and returns the host without port.
// Returns ("", false) if the scheme is not http/https or the URL is unparseable.
func parseURLDomain(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}

	// Only accept http and https schemes.
	if !acceptedSchemes[strings.ToLower(u.Scheme)] {
		return "", false
	}

	// u.Hostname() correctly strips brackets from IPv6 literals like [::1]
	// and strips the port if present.
	host := strings.ToLower(u.Hostname())

	if host == "" {
		return "", false
	}

	return host, true
}
