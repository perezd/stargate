// Package adapter provides agent-specific hook adapters and supporting utilities.
package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// TraceData is the minimal schema stored between pre and post tool use.
type TraceData struct {
	StargateTrID  string `json:"stargate_trace_id"`
	FeedbackToken string `json:"feedback_token"`
	ToolUseID     string `json:"tool_use_id"`
}

// TraceNotFoundError is returned by ReadTrace when the trace file does not exist.
type TraceNotFoundError struct {
	ToolUseID string
}

func (e *TraceNotFoundError) Error() string {
	return fmt.Sprintf("trace not found for tool_use_id %q", e.ToolUseID)
}

var toolUseIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateToolUseID checks the ID is safe for filesystem use.
// Returns error if empty or doesn't match ^[a-zA-Z0-9_-]+$.
func ValidateToolUseID(id string) error {
	if id == "" {
		return errors.New("tool_use_id must not be empty")
	}
	if !toolUseIDPattern.MatchString(id) {
		return fmt.Errorf("tool_use_id %q contains invalid characters: must match ^[a-zA-Z0-9_-]+$", id)
	}
	return nil
}

// TraceDir returns the trace directory path, creating it with 0700 if needed.
// Resolution: $XDG_RUNTIME_DIR/stargate if set, else $TMPDIR/stargate-$UID.
// Falls back to os.TempDir() + "/stargate-" + strconv.Itoa(os.Getuid()).
func TraceDir() (string, error) {
	var dir string
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		dir = filepath.Join(xdg, "stargate")
	} else {
		uid := strconv.Itoa(os.Getuid())
		dir = filepath.Join(os.TempDir(), "stargate-"+uid)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating trace directory %q: %w", dir, err)
	}

	// Explicitly set permissions in case directory already existed with wrong perms.
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("setting trace directory permissions on %q: %w", dir, err)
	}

	// Verify via Lstat that the result is a real directory (not a symlink).
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("verifying trace directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("trace directory path %q exists but is not a directory", dir)
	}

	return dir, nil
}

// WriteTrace writes trace data to <dir>/<tool_use_id>.json.
// Uses O_WRONLY|O_CREATE|O_TRUNC|syscall.O_NOFOLLOW with 0600 permissions.
func WriteTrace(dir string, data TraceData) error {
	if err := ValidateToolUseID(data.ToolUseID); err != nil {
		return fmt.Errorf("WriteTrace: %w", err)
	}

	path := filepath.Join(dir, data.ToolUseID+".json")
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC | syscall.O_NOFOLLOW
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return fmt.Errorf("opening trace file %q: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encoding trace data to %q: %w", path, err)
	}
	return nil
}

// ReadTrace reads trace data from <dir>/<tool_use_id>.json.
// Uses O_RDONLY|syscall.O_NOFOLLOW.
// Returns *TraceNotFoundError for missing files.
func ReadTrace(dir, toolUseID string) (TraceData, error) {
	if err := ValidateToolUseID(toolUseID); err != nil {
		return TraceData{}, fmt.Errorf("ReadTrace: %w", err)
	}

	path := filepath.Join(dir, toolUseID+".json")
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return TraceData{}, &TraceNotFoundError{ToolUseID: toolUseID}
		}
		return TraceData{}, fmt.Errorf("opening trace file %q: %w", path, err)
	}
	defer f.Close()

	var data TraceData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return TraceData{}, fmt.Errorf("decoding trace data from %q: %w", path, err)
	}
	return data, nil
}

// DeleteTrace removes the trace file. Returns nil if file doesn't exist.
func DeleteTrace(dir, toolUseID string) error {
	if err := ValidateToolUseID(toolUseID); err != nil {
		return fmt.Errorf("DeleteTrace: %w", err)
	}

	path := filepath.Join(dir, toolUseID+".json")
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing trace file %q: %w", path, err)
	}
	return nil
}

// CleanupOrphans removes regular files older than maxAge in dir.
// Uses os.Lstat (not os.Stat) — skips symlinks and non-regular files.
func CleanupOrphans(dir string, maxAge time.Duration) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading trace directory %q: %w", dir, err)
	}

	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		// Use Lstat to avoid following symlinks.
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			// File may have been removed between ReadDir and Lstat; skip.
			continue
		}

		// Skip symlinks and non-regular files.
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("removing orphan trace file %q: %w", path, err)
			}
		}
	}
	return nil
}
