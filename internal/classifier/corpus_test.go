package classifier_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perezd/stargate/internal/classifier"
	"github.com/perezd/stargate/internal/config"
)

// TestCorpus classifies every command in the testdata corpus files against the
// real stargate.toml config and asserts the expected decision. All failures are
// reported together (t.Errorf, not t.Fatalf) so a single run surfaces the full
// set of divergences.
func TestCorpus(t *testing.T) {
	cfg, err := config.Load("../../stargate.toml")
	if err != nil {
		t.Fatalf("failed to load stargate.toml: %v", err)
	}

	clf, err := classifier.New(cfg)
	if err != nil {
		t.Fatalf("classifier init failed: %v", err)
	}

	files := []string{
		"../../testdata/red_commands.txt",
		"../../testdata/green_commands.txt",
		"../../testdata/yellow_commands.txt",
		"../../testdata/evasion_commands.txt",
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}

			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := strings.TrimSpace(scanner.Text())

				// Skip blank lines and comments.
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// Each line is: <command><TAB><expected_decision>
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) != 2 {
					t.Errorf("line %d: malformed entry (expected tab-separated command and decision): %q", lineNum, line)
					continue
				}

				command := strings.TrimSpace(parts[0])
				want := strings.TrimSpace(parts[1])

				resp := clf.Classify(classifier.ClassifyRequest{Command: command})
				if resp.Decision != want {
					t.Errorf("line %d: %q => got %q, want %q (reason: %s)",
						lineNum, command, resp.Decision, want, resp.Reason)
				}
			}

			if err := scanner.Err(); err != nil {
				t.Fatalf("scan %s: %v", file, err)
			}
		})
	}
}
