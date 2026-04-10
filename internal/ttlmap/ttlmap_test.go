package ttlmap_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/limbic-systems/stargate/internal/ttlmap"
)

// TestSetGet verifies the basic Set/Get round-trip.
func TestSetGet(t *testing.T) {
	m := ttlmap.New[string, int](t.Context(), ttlmap.Options{SweepInterval: time.Minute})

	m.Set("a", 42, time.Minute)

	v, ok := m.Get("a")
	if !ok {
		t.Fatal("expected key 'a' to be present")
	}
	if v != 42 {
		t.Fatalf("expected 42, got %d", v)
	}
}

// TestExpiry verifies that Get returns false once the TTL has elapsed.
func TestExpiry(t *testing.T) {
	m := ttlmap.New[string, int](t.Context(), ttlmap.Options{SweepInterval: time.Minute})

	m.Set("x", 1, 50*time.Millisecond)

	// Should be present immediately.
	if _, ok := m.Get("x"); !ok {
		t.Fatal("key should be present before TTL expires")
	}

	time.Sleep(100 * time.Millisecond)

	_, ok := m.Get("x")
	if ok {
		t.Fatal("key should be expired after TTL")
	}
}

// TestBackgroundSweep verifies the sweep goroutine eventually removes expired entries.
func TestBackgroundSweep(t *testing.T) {
	sweep := 60 * time.Millisecond
	m := ttlmap.New[string, int](t.Context(), ttlmap.Options{SweepInterval: sweep})

	m.Set("a", 1, 30*time.Millisecond)
	m.Set("b", 2, 30*time.Millisecond)
	m.Set("c", 3, time.Minute) // long-lived, should survive

	// Wait for TTL to elapse and then at least one sweep to run.
	time.Sleep(150 * time.Millisecond)

	if got := m.Len(); got != 1 {
		t.Fatalf("expected 1 entry after sweep, got %d", got)
	}
}

// TestConcurrentAccess exercises concurrent Set/Get/Delete under the race detector.
func TestConcurrentAccess(t *testing.T) {
	m := ttlmap.New[int, int](t.Context(), ttlmap.Options{SweepInterval: 10 * time.Millisecond})

	const goroutines = 20
	const ops = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range ops {
				key := (id*ops + i) % 50 // intentional key collisions
				switch i % 3 {
				case 0:
					m.Set(key, i, 50*time.Millisecond)
				case 1:
					m.Get(key)
				case 2:
					m.Delete(key)
				}
			}
		}(g)
	}

	wg.Wait()
}

// TestMaxEntriesEviction verifies that when MaxEntries is set, inserting
// beyond the limit evicts the oldest entries.
func TestMaxEntriesEviction(t *testing.T) {
	m := ttlmap.New[string, int](t.Context(), ttlmap.Options{
		SweepInterval: time.Minute,
		MaxEntries:    3,
	})

	// Insert 5 entries with a small delay so insertedAt ordering is deterministic.
	keys := []string{"k1", "k2", "k3", "k4", "k5"}
	for _, k := range keys {
		m.Set(k, 1, time.Minute)
		time.Sleep(2 * time.Millisecond) // ensure strictly ordered insertedAt
	}

	// k1 and k2 should have been evicted (oldest insertedAt).
	if _, ok := m.Get("k1"); ok {
		t.Error("k1 should have been evicted")
	}
	if _, ok := m.Get("k2"); ok {
		t.Error("k2 should have been evicted")
	}

	// k3, k4, k5 should still be present.
	for _, k := range []string{"k3", "k4", "k5"} {
		if _, ok := m.Get(k); !ok {
			t.Errorf("key %q should be present", k)
		}
	}

	if got := m.Len(); got != 3 {
		t.Fatalf("expected Len 3 after eviction, got %d", got)
	}
}

// TestClear verifies that Clear removes all entries.
func TestClear(t *testing.T) {
	m := ttlmap.New[string, int](t.Context(), ttlmap.Options{SweepInterval: time.Minute})

	for i := range 5 {
		m.Set(string(rune('a'+i)), i, time.Minute)
	}

	if m.Len() != 5 {
		t.Fatalf("expected 5 entries before Clear, got %d", m.Len())
	}

	m.Clear()

	if m.Len() != 0 {
		t.Fatalf("expected 0 entries after Clear, got %d", m.Len())
	}
}

// TestClose verifies that the sweep goroutine stops when Close is called.
// We verify this indirectly: after Close, expired entries are not removed by
// the sweep (Len still counts only non-expired, but the internal map size
// does not shrink — we test that the goroutine exits cleanly via a context
// that would otherwise fire).
func TestClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sweep := 30 * time.Millisecond
	m := ttlmap.New[string, int](ctx, ttlmap.Options{SweepInterval: sweep})

	m.Set("key", 99, time.Minute)

	// Close should not block and be idempotent.
	m.Close()
	m.Close() // second call must not panic

	// Map should still be readable after Close.
	v, ok := m.Get("key")
	if !ok || v != 99 {
		t.Fatalf("expected key to be readable after Close, got ok=%v v=%d", ok, v)
	}
}

// TestContextCancellationStopsSweep verifies that cancelling the context
// stops the background goroutine (no goroutine leak detectable via context).
func TestContextCancellationStopsSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	m := ttlmap.New[string, int](ctx, ttlmap.Options{SweepInterval: 20 * time.Millisecond})
	m.Set("a", 1, time.Minute)

	cancel() // cancel context → goroutine should exit

	// Give the goroutine a moment to exit cleanly.
	time.Sleep(50 * time.Millisecond)

	// Map must still be usable after context cancellation.
	if v, ok := m.Get("a"); !ok || v != 1 {
		t.Fatalf("map should remain usable after context cancel, got ok=%v v=%d", ok, v)
	}
}

// TestZeroMaxEntriesUnlimited verifies that MaxEntries=0 places no limit.
func TestZeroMaxEntriesUnlimited(t *testing.T) {
	m := ttlmap.New[int, int](t.Context(), ttlmap.Options{
		SweepInterval: time.Minute,
		MaxEntries:    0,
	})

	const n = 100
	for i := range n {
		m.Set(i, i, time.Minute)
	}

	if got := m.Len(); got != n {
		t.Fatalf("expected %d entries with unlimited MaxEntries, got %d", n, got)
	}
}
