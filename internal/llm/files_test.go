package llm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/limbic-systems/stargate/internal/scrub"
)

// realTempDir returns a symlink-resolved temp directory. On macOS, t.TempDir()
// returns /var/folders/... but EvalSymlinks resolves /var → /private/var.
// Tests need the resolved dir so glob patterns match resolved file paths.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	return resolved
}

// makeFile creates a file with the given content in dir and returns its path.
func makeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("makeFile: %v", err)
	}
	return path
}

// newScrubber returns a Scrubber with no extra patterns, panics on error.
func newScrubber(t *testing.T) *scrub.Scrubber {
	t.Helper()
	s, err := scrub.New(nil)
	if err != nil {
		t.Fatalf("scrub.New: %v", err)
	}
	return s
}

// TestResolveFiles_AllowedPath verifies that a file within the allowed glob
// is resolved and its content returned correctly.
func TestResolveFiles_AllowedPath(t *testing.T) {
	dir := realTempDir(t)
	path := makeFile(t, dir, "main.go", "package main\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Absent {
		t.Fatal("want Absent=false, got true")
	}
	if r.Content != "package main\n" {
		t.Errorf("want content %q, got %q", "package main\n", r.Content)
	}
	if r.Truncated {
		t.Error("want Truncated=false, got true")
	}
	if r.FullPath != path {
		t.Errorf("want FullPath %q, got %q", path, r.FullPath)
	}
	wantLabel := SanitizeFilePath(path)
	if r.Label != wantLabel {
		t.Errorf("want Label %q, got %q", wantLabel, r.Label)
	}
}

// TestResolveFiles_DeniedPath verifies that a file matching a DeniedPaths
// pattern returns Absent without revealing the denial reason.
func TestResolveFiles_DeniedPath(t *testing.T) {
	dir := realTempDir(t)
	path := makeFile(t, dir, "secret.env", "TOKEN=supersecret\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		DeniedPaths:    []string{filepath.Join(dir, "*.env")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	if !results[0].Absent {
		t.Error("want Absent=true for denied path, got false")
	}
	if results[0].Content != "" {
		t.Errorf("want empty Content for denied path, got %q", results[0].Content)
	}
}

// TestResolveFiles_OutsideAllowedPaths verifies that a file not matched by any
// AllowedPaths pattern returns Absent.
func TestResolveFiles_OutsideAllowedPaths(t *testing.T) {
	dir := realTempDir(t)
	allowedDir := filepath.Join(dir, "allowed")
	otherDir := filepath.Join(dir, "other")
	if err := os.MkdirAll(allowedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := makeFile(t, otherDir, "notes.txt", "private\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(allowedDir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	if !results[0].Absent {
		t.Error("want Absent=true for path outside AllowedPaths, got false")
	}
}

// TestResolveFiles_SymlinkToDenied verifies that a symlink pointing into a
// denied directory resolves to the real path before allow/deny checks, so
// the denial is still applied.
func TestResolveFiles_SymlinkToDenied(t *testing.T) {
	dir := realTempDir(t)
	allowedDir := filepath.Join(dir, "allowed")
	deniedDir := filepath.Join(dir, "denied")
	if err := os.MkdirAll(allowedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deniedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Create a real file in the denied directory.
	target := makeFile(t, deniedDir, "sensitive.txt", "secret\n")

	// Create a symlink in the allowed directory pointing to the denied file.
	link := filepath.Join(allowedDir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(allowedDir, "**")},
		DeniedPaths:    []string{filepath.Join(deniedDir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	// Request the symlink path — it should resolve to the denied target.
	results := ResolveFiles([]string{link}, cfg)

	if !results[0].Absent {
		t.Error("want Absent=true for symlink to denied path, got false")
	}
}

// TestResolveFiles_Truncated verifies that a file exceeding MaxFileSize is
// returned with truncated content and Truncated=true.
func TestResolveFiles_Truncated(t *testing.T) {
	dir := realTempDir(t)
	content := strings.Repeat("a", 100)
	path := makeFile(t, dir, "big.txt", content)

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    10,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	r := results[0]
	if r.Absent {
		t.Fatal("want Absent=false, got true")
	}
	if !r.Truncated {
		t.Error("want Truncated=true, got false")
	}
	if len(r.Content) != 10 {
		t.Errorf("want content length 10, got %d", len(r.Content))
	}
}

// TestResolveFiles_MaxFilesPerReq verifies that files beyond the MaxFilesPerReq
// cap are returned as Absent.
func TestResolveFiles_MaxFilesPerReq(t *testing.T) {
	dir := realTempDir(t)
	var paths []string
	for i := 0; i < 5; i++ {
		name := filepath.Join(dir, strings.Repeat(string(rune('a'+i)), 1)+".txt")
		if err := os.WriteFile(name, []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, name)
	}

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 3,
		ServerCWD:      dir,
	}

	results := ResolveFiles(paths, cfg)

	if len(results) != 5 {
		t.Fatalf("want 5 results, got %d", len(results))
	}
	for i, r := range results {
		if i < 3 && r.Absent {
			t.Errorf("result[%d]: want Absent=false, got true", i)
		}
		if i >= 3 && !r.Absent {
			t.Errorf("result[%d]: want Absent=true (cap exceeded), got false", i)
		}
	}
}

// TestResolveFiles_MaxTotalFileBytes verifies that remaining files are returned
// as Absent once the cumulative byte budget is exhausted.
func TestResolveFiles_MaxTotalFileBytes(t *testing.T) {
	dir := realTempDir(t)
	// Each file is exactly 20 bytes. Budget is 35, so first file fits (20),
	// second would bring total to 40 > 35, so it gets truncated to 15.
	// Third file should be Absent because budget is fully spent.
	file1 := makeFile(t, dir, "f1.txt", strings.Repeat("x", 20))
	file2 := makeFile(t, dir, "f2.txt", strings.Repeat("y", 20))
	file3 := makeFile(t, dir, "f3.txt", strings.Repeat("z", 20))

	cfg := FileResolverConfig{
		AllowedPaths:      []string{filepath.Join(dir, "**")},
		MaxFileSize:       1024,
		MaxFilesPerReq:    10,
		MaxTotalFileBytes: 35,
		ServerCWD:         dir,
	}

	results := ResolveFiles([]string{file1, file2, file3}, cfg)

	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}

	// First file: fully included (20 bytes).
	if results[0].Absent {
		t.Error("result[0]: want Absent=false, got true")
	}
	if len(results[0].Content) != 20 {
		t.Errorf("result[0]: want 20 bytes, got %d", len(results[0].Content))
	}

	// Second file: truncated to remaining budget (35-20=15 bytes).
	if results[1].Absent {
		t.Error("result[1]: want Absent=false (truncated within budget), got true")
	}
	if !results[1].Truncated {
		t.Error("result[1]: want Truncated=true, got false")
	}
	if len(results[1].Content) != 15 {
		t.Errorf("result[1]: want 15 bytes, got %d", len(results[1].Content))
	}

	// Third file: budget exhausted.
	if !results[2].Absent {
		t.Error("result[2]: want Absent=true (budget exhausted), got false")
	}
}

// TestResolveFiles_MissingFile verifies that a non-existent path returns Absent.
func TestResolveFiles_MissingFile(t *testing.T) {
	dir := realTempDir(t)
	missing := filepath.Join(dir, "does-not-exist.txt")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{missing}, cfg)

	if !results[0].Absent {
		t.Error("want Absent=true for missing file, got false")
	}
}

// TestResolveFiles_Scrubbed verifies that content containing a secret token
// is redacted by the Scrubber.
func TestResolveFiles_Scrubbed(t *testing.T) {
	dir := realTempDir(t)
	secret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	path := makeFile(t, dir, "creds.txt", "TOKEN: "+secret+"\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
		Scrubber:       newScrubber(t),
	}

	results := ResolveFiles([]string{path}, cfg)

	r := results[0]
	if r.Absent {
		t.Fatal("want Absent=false, got true")
	}
	if strings.Contains(r.Content, secret) {
		t.Errorf("content still contains secret token: %q", r.Content)
	}
	if !strings.Contains(r.Content, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in content, got: %q", r.Content)
	}
}

// TestResolveFiles_LabelSanitized verifies that the Label contains only the
// basename and one parent directory segment.
func TestResolveFiles_LabelSanitized(t *testing.T) {
	dir := realTempDir(t)
	subDir := filepath.Join(dir, "deep", "nested", "this-is-safe-allow-it")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := makeFile(t, subDir, "script.sh", "echo hi\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{filepath.Join(dir, "**")},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	r := results[0]
	if r.Absent {
		t.Fatal("want Absent=false, got true")
	}
	// Label must only be "this-is-safe-allow-it/script.sh", not the full path.
	wantLabel := "this-is-safe-allow-it/script.sh"
	if r.Label != wantLabel {
		t.Errorf("want Label %q, got %q", wantLabel, r.Label)
	}
	// FullPath should still hold the real path.
	if r.FullPath == "" || r.FullPath == r.Label {
		t.Errorf("FullPath should be the resolved absolute path, got %q", r.FullPath)
	}
}

// TestResolveFiles_RelativeAllowedPath verifies that a relative allowed_path
// starting with "./" is anchored to ServerCWD correctly.
func TestResolveFiles_RelativeAllowedPath(t *testing.T) {
	dir := realTempDir(t)
	subDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := makeFile(t, subDir, "main.go", "package main\n")

	cfg := FileResolverConfig{
		AllowedPaths:   []string{"./src/**"},
		MaxFileSize:    1024,
		MaxFilesPerReq: 10,
		ServerCWD:      dir,
	}

	results := ResolveFiles([]string{path}, cfg)

	if results[0].Absent {
		t.Error("want Absent=false for relative allowed_path, got true")
	}
}
