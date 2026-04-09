package llm

import (
	"io"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/limbic-systems/stargate/internal/scrub"
)

// FileResolverConfig configures the file resolver.
type FileResolverConfig struct {
	AllowedPaths      []string         // glob patterns, anchored to ServerCWD
	DeniedPaths       []string         // glob patterns
	MaxFileSize       int              // per-file size limit in bytes
	MaxFilesPerReq    int              // max files per LLM request
	MaxTotalFileBytes int              // total bytes across all files
	ServerCWD         string           // anchor for relative allowed_paths (set at server startup)
	Scrubber          *scrub.Scrubber  // for secret redaction of file contents
}

// FileResult represents a resolved file.
type FileResult struct {
	Label     string // sanitized: basename + parent dir only (use llm.SanitizeFilePath)
	FullPath  string // for files_inspected in API response
	Content   string // scrubbed content
	Truncated bool   // true if file was truncated to MaxFileSize
	Absent    bool   // true if file missing, denied, or beyond budget
}

// ResolveFiles resolves and validates each requested file path, applying
// allow/deny glob checks, size limits, budget tracking, and secret scrubbing.
//
// Security properties:
//   - Symlinks are resolved via filepath.EvalSymlinks before any validation,
//     preventing symlink-based traversal into denied paths.
//   - Absent is returned (without explanation) for missing, denied, and
//     budget-exceeded files to avoid leaking path information.
//   - AllowedPaths patterns are anchored to cfg.ServerCWD to prevent the LLM
//     from requesting files outside the operator-configured boundary.
func ResolveFiles(paths []string, cfg FileResolverConfig) []FileResult {
	results := make([]FileResult, len(paths))
	totalBytes := 0

	for i, p := range paths {
		// Step 1: Enforce MaxFilesPerReq cap.
		if cfg.MaxFilesPerReq > 0 && i >= cfg.MaxFilesPerReq {
			results[i] = FileResult{Absent: true}
			continue
		}

		// Step 2: Resolve path to absolute using ServerCWD.
		absPath := p
		if !filepath.IsAbs(p) {
			absPath = filepath.Join(cfg.ServerCWD, p)
		}

		// Step 3: Resolve symlinks — failure means Absent.
		resolved, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			results[i] = FileResult{Absent: true}
			continue
		}

		// Step 4: Validate against AllowedPaths and DeniedPaths.
		if !isAllowed(resolved, cfg) {
			results[i] = FileResult{Absent: true}
			continue
		}

		// Step 6: Check cumulative budget before reading.
		if cfg.MaxTotalFileBytes > 0 && totalBytes >= cfg.MaxTotalFileBytes {
			results[i] = FileResult{Absent: true}
			continue
		}

		// Step 5: Read file up to MaxFileSize.
		content, truncated, err := readFile(resolved, cfg.MaxFileSize)
		if err != nil {
			results[i] = FileResult{Absent: true}
			continue
		}

		// Step 6 (continued): Track cumulative bytes. If adding this file's
		// content would exceed the budget, truncate to the remaining budget.
		if cfg.MaxTotalFileBytes > 0 {
			remaining := cfg.MaxTotalFileBytes - totalBytes
			if len(content) > remaining {
				content = content[:remaining]
				truncated = true
			}
		}
		totalBytes += len(content)

		// Step 7: Scrub content.
		text := string(content)
		if cfg.Scrubber != nil {
			text = cfg.Scrubber.Text(text)
		}

		// Step 8: Build sanitized label.
		results[i] = FileResult{
			Label:     SanitizeFilePath(resolved),
			FullPath:  resolved,
			Content:   text,
			Truncated: truncated,
		}
	}

	return results
}

// isAllowed returns true if resolved path passes the allow/deny glob checks.
// A path must match at least one AllowedPaths pattern and must not match any
// DeniedPaths pattern. If AllowedPaths is empty, no files are allowed.
func isAllowed(resolved string, cfg FileResolverConfig) bool {
	// Must match at least one allowed pattern.
	allowed := false
	for _, pattern := range cfg.AllowedPaths {
		pat := anchorPattern(pattern, cfg.ServerCWD)
		matched, err := doublestar.Match(pat, resolved)
		if err == nil && matched {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	// Must not match any denied pattern.
	for _, pattern := range cfg.DeniedPaths {
		pat := anchorPattern(pattern, cfg.ServerCWD)
		matched, err := doublestar.Match(pat, resolved)
		if err == nil && matched {
			return false
		}
	}

	return true
}

// anchorPattern resolves a glob pattern relative to base if the pattern
// starts with "./" or is otherwise relative (non-absolute and no "**" prefix).
func anchorPattern(pattern, base string) string {
	if filepath.IsAbs(pattern) {
		return pattern
	}
	// Relative pattern — resolve against base.
	return filepath.Join(base, pattern)
}

// readFile reads up to maxBytes from path. If maxBytes <= 0, the entire file
// is read. Returns the content, whether it was truncated, and any error.
func readFile(path string, maxBytes int) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	if maxBytes <= 0 {
		data, err := io.ReadAll(f)
		return data, false, err
	}

	// Read one extra byte to detect truncation without a stat call.
	buf := make([]byte, maxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, false, err
	}

	truncated := n > maxBytes
	if truncated {
		return buf[:maxBytes], true, nil
	}
	return buf[:n], false, nil
}
