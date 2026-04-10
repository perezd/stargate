package classifier

import (
	"testing"
	"time"
)

func TestCommandCache(t *testing.T) {
	t.Run("miss returns false", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		_, ok := cc.Lookup("ls -la", "/home/user")
		if ok {
			t.Fatal("expected miss, got hit")
		}
	})

	t.Run("hit after store", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		got, ok := cc.Lookup("ls -la", "/home/user")
		if !ok {
			t.Fatal("expected hit, got miss")
		}
		if got.Decision != "green" {
			t.Errorf("Decision: got %q, want %q", got.Decision, "green")
		}
		if got.Action != "allow" {
			t.Errorf("Action: got %q, want %q", got.Action, "allow")
		}
	})

	t.Run("different command same CWD is a miss", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		_, ok := cc.Lookup("rm -rf /", "/home/user")
		if ok {
			t.Fatal("expected miss for different command, got hit")
		}
	})

	t.Run("same command different CWD is a miss", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		_, ok := cc.Lookup("ls -la", "/tmp")
		if ok {
			t.Fatal("expected miss for different CWD, got hit")
		}
	})

	t.Run("scrubbing collision prevention", func(t *testing.T) {
		// Two commands that differ only in a token that would scrub to [REDACTED].
		// Because we key on the raw command, they must produce different cache keys.
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		cmd1 := "curl -H 'Authorization: Bearer token-abc123' https://api.example.com"
		cmd2 := "curl -H 'Authorization: Bearer token-xyz789' https://api.example.com"
		cc.Store(cmd1, "/home/user", "yellow", "review")
		// cmd2 would scrub to the same string as cmd1, but we use raw commands.
		_, ok := cc.Lookup(cmd2, "/home/user")
		if ok {
			t.Fatal("expected miss: different raw commands should not collide even if they scrub identically")
		}
	})

	t.Run("entry expires after TTL", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 50*time.Millisecond, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		// Verify it's present.
		_, ok := cc.Lookup("ls -la", "/home/user")
		if !ok {
			t.Fatal("expected hit before TTL expiry")
		}
		// Wait for expiry.
		time.Sleep(100 * time.Millisecond)
		_, ok = cc.Lookup("ls -la", "/home/user")
		if ok {
			t.Fatal("expected miss after TTL expiry")
		}
	})

	t.Run("clear empties cache", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		cc.Store("pwd", "/home/user", "green", "allow")
		cc.Clear()
		_, ok1 := cc.Lookup("ls -la", "/home/user")
		_, ok2 := cc.Lookup("pwd", "/home/user")
		if ok1 || ok2 {
			t.Fatal("expected all entries evicted after Clear")
		}
	})

	t.Run("disabled cache ttl=0: store is no-op, lookup always false", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 0, 100)
		cc.Store("ls -la", "/home/user", "green", "allow")
		_, ok := cc.Lookup("ls -la", "/home/user")
		if ok {
			t.Fatal("expected miss from disabled cache (ttl=0)")
		}
		// Clear on disabled cache must not panic.
		cc.Clear()
	})

	t.Run("disabled cache maxEntries=0: store is no-op, lookup always false", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 0)
		cc.Store("ls -la", "/home/user", "green", "allow")
		_, ok := cc.Lookup("ls -la", "/home/user")
		if ok {
			t.Fatal("expected miss from disabled cache (maxEntries=0)")
		}
	})

	t.Run("maxEntries eviction evicts oldest", func(t *testing.T) {
		cc := NewCommandCache(t.Context(), 5*time.Minute, 3)
		// Store 3 entries to fill the cache.
		cc.Store("cmd-a", "/", "green", "allow")
		time.Sleep(2 * time.Millisecond) // ensure distinct insertedAt
		cc.Store("cmd-b", "/", "green", "allow")
		time.Sleep(2 * time.Millisecond)
		cc.Store("cmd-c", "/", "green", "allow")
		// All three should be present.
		for _, cmd := range []string{"cmd-a", "cmd-b", "cmd-c"} {
			if _, ok := cc.Lookup(cmd, "/"); !ok {
				t.Fatalf("expected %q to be present before eviction", cmd)
			}
		}
		// Adding a 4th entry should evict cmd-a (oldest).
		time.Sleep(2 * time.Millisecond)
		cc.Store("cmd-d", "/", "green", "allow")
		if _, ok := cc.Lookup("cmd-a", "/"); ok {
			t.Fatal("expected cmd-a to be evicted as the oldest entry")
		}
		// cmd-b, cmd-c, cmd-d should still be present.
		for _, cmd := range []string{"cmd-b", "cmd-c", "cmd-d"} {
			if _, ok := cc.Lookup(cmd, "/"); !ok {
				t.Fatalf("expected %q to still be present after eviction", cmd)
			}
		}
	})
}
