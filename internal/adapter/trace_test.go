package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleTrace(toolUseID string) TraceData {
	return TraceData{
		StargateTrID:  "tr-abc123",
		FeedbackToken: "tok-xyz",
		ToolUseID:     toolUseID,
	}
}

// 1. WriteTrace + ReadTrace round-trip
func TestWriteReadTrace_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := sampleTrace("toolu_01ABC")

	if err := WriteTrace(dir, want); err != nil {
		t.Fatalf("WriteTrace: %v", err)
	}

	got, err := ReadTrace(dir, want.ToolUseID)
	if err != nil {
		t.Fatalf("ReadTrace: %v", err)
	}

	if got != want {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

// 2. WriteTrace creates file with 0600 permissions
func TestWriteTrace_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	data := sampleTrace("toolu_perms")

	if err := WriteTrace(dir, data); err != nil {
		t.Fatalf("WriteTrace: %v", err)
	}

	path := filepath.Join(dir, data.ToolUseID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions: got %04o, want 0600", perm)
	}
}

// 3. ReadTrace on missing file returns identifiable error
func TestReadTrace_MissingFile(t *testing.T) {
	dir := t.TempDir()

	_, err := ReadTrace(dir, "toolu_missing")
	if err == nil {
		t.Fatal("expected error for missing trace file, got nil")
	}

	var notFound *TraceNotFoundError
	if !errors.As(err, &notFound) {
		t.Errorf("expected *TraceNotFoundError, got %T: %v", err, err)
	}
	if notFound.ToolUseID != "toolu_missing" {
		t.Errorf("TraceNotFoundError.ToolUseID: got %q, want %q", notFound.ToolUseID, "toolu_missing")
	}
}

// 4. ReadTrace with symlink present → error (O_NOFOLLOW)
func TestReadTrace_Symlink(t *testing.T) {
	dir := t.TempDir()
	toolUseID := "toolu_symlink_read"

	// Create a real file to point to.
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{"stargate_trace_id":"x","feedback_token":"y","tool_use_id":"toolu_symlink_read"}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create symlink at the expected trace path.
	link := filepath.Join(dir, toolUseID+".json")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink creation not supported:", err)
	}

	_, err := ReadTrace(dir, toolUseID)
	if err == nil {
		t.Error("expected error when reading through symlink, got nil")
	}
}

// 5. WriteTrace with symlink at target → error (O_NOFOLLOW)
func TestWriteTrace_Symlink(t *testing.T) {
	dir := t.TempDir()
	toolUseID := "toolu_symlink_write"

	// Create a real file to point to.
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Place a symlink at the expected trace path.
	link := filepath.Join(dir, toolUseID+".json")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink creation not supported:", err)
	}

	err := WriteTrace(dir, sampleTrace(toolUseID))
	if err == nil {
		t.Error("expected error when writing through symlink, got nil")
	}
}

// 6. DeleteTrace removes file
func TestDeleteTrace_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	data := sampleTrace("toolu_delete")

	if err := WriteTrace(dir, data); err != nil {
		t.Fatalf("WriteTrace: %v", err)
	}

	if err := DeleteTrace(dir, data.ToolUseID); err != nil {
		t.Fatalf("DeleteTrace: %v", err)
	}

	path := filepath.Join(dir, data.ToolUseID+".json")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected file to be gone; Lstat returned: %v", err)
	}
}

// 7. DeleteTrace on missing file → no error
func TestDeleteTrace_MissingFile_NoError(t *testing.T) {
	dir := t.TempDir()

	if err := DeleteTrace(dir, "toolu_nonexistent"); err != nil {
		t.Errorf("DeleteTrace on missing file: got error %v, want nil", err)
	}
}

// 8. ValidateToolUseID: "toolu_01ABC" passes
func TestValidateToolUseID_Valid(t *testing.T) {
	if err := ValidateToolUseID("toolu_01ABC"); err != nil {
		t.Errorf("expected nil for valid ID, got: %v", err)
	}
}

// 9. ValidateToolUseID: "../../etc/evil" rejected
func TestValidateToolUseID_PathTraversal(t *testing.T) {
	if err := ValidateToolUseID("../../etc/evil"); err == nil {
		t.Error("expected error for path traversal ID, got nil")
	}
}

// 10. ValidateToolUseID: "" rejected
func TestValidateToolUseID_Empty(t *testing.T) {
	if err := ValidateToolUseID(""); err == nil {
		t.Error("expected error for empty ID, got nil")
	}
}

// 11. ValidateToolUseID: "has spaces" rejected
func TestValidateToolUseID_Spaces(t *testing.T) {
	if err := ValidateToolUseID("has spaces"); err == nil {
		t.Error("expected error for ID with spaces, got nil")
	}
}

// 12. TraceDir creates directory with 0700
func TestTraceDir_Permissions(t *testing.T) {
	// Override XDG_RUNTIME_DIR to use a temp location we control.
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", tmp)

	dir, err := TraceDir()
	if err != nil {
		t.Fatalf("TraceDir: %v", err)
	}

	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	if !info.IsDir() {
		t.Error("TraceDir result is not a directory")
	}

	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("directory permissions: got %04o, want 0700", perm)
	}
}

// 13. CleanupOrphans: old files deleted, young files preserved
func TestCleanupOrphans_AgeFiltering(t *testing.T) {
	dir := t.TempDir()

	// Write two trace files.
	old := sampleTrace("toolu_old")
	young := sampleTrace("toolu_young")
	for _, d := range []TraceData{old, young} {
		if err := WriteTrace(dir, d); err != nil {
			t.Fatalf("WriteTrace %s: %v", d.ToolUseID, err)
		}
	}

	// Back-date the "old" file by 2 hours.
	oldPath := filepath.Join(dir, old.ToolUseID+".json")
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	maxAge := 1 * time.Hour
	if err := CleanupOrphans(dir, maxAge); err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}

	// Old file should be gone.
	if _, err := os.Lstat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected old file to be removed; Lstat returned: %v", err)
	}

	// Young file should still exist.
	youngPath := filepath.Join(dir, young.ToolUseID+".json")
	if _, err := os.Lstat(youngPath); err != nil {
		t.Errorf("expected young file to remain; Lstat returned: %v", err)
	}
}

// 14. CleanupOrphans: symlinks skipped (not deleted, not followed)
func TestCleanupOrphans_SkipsSymlinks(t *testing.T) {
	// Use two separate temp dirs: one for the trace dir, one for the symlink target.
	// This ensures CleanupOrphans cannot accidentally delete the target as a regular file.
	traceDir := t.TempDir()
	externalDir := t.TempDir()

	// Create a real file in the external dir (outside the trace dir).
	target := filepath.Join(externalDir, "target.txt")
	if err := os.WriteFile(target, []byte("sensitive"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create a symlink inside the trace dir pointing to the external target.
	link := filepath.Join(traceDir, "toolu_link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation not supported:", err)
	}

	// Back-date the external target so that if CleanupOrphans mistakenly follows the
	// symlink and deletes the resolved file, we'd detect it.
	past := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(target, past, past)

	if err := CleanupOrphans(traceDir, 1*time.Hour); err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}

	// Symlink must still exist — CleanupOrphans must not have deleted it.
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("symlink was unexpectedly removed or inaccessible: %v", err)
	}

	// Target file must still exist — symlink must not have been followed.
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("target was unexpectedly removed or inaccessible: %v", err)
	}
}
