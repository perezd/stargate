// Package ttlmap provides a generic TTL-based map with background sweep and
// LRU eviction by insertion time.
package ttlmap

import (
	"context"
	"sync"
	"time"
)

const (
	defaultSweepInterval = 30 * time.Second
)

// Options configures a TTLMap.
type Options struct {
	// SweepInterval controls how often the background goroutine removes expired
	// entries. Defaults to max(defaultTTL/10, 30s) — callers should set this
	// explicitly when they have a known TTL budget.
	SweepInterval time.Duration

	// MaxEntries limits the number of live entries. When a Set would exceed
	// this limit, the entry with the oldest insertedAt is evicted first.
	// Zero means unlimited.
	MaxEntries int
}

// entry holds a stored value together with its expiry and insertion metadata.
type entry[V any] struct {
	value      V
	expiresAt  time.Time
	insertedAt time.Time
}

// TTLMap is a generic, thread-safe map whose entries expire after a
// caller-supplied TTL. A background sweep goroutine periodically removes
// stale entries; lazy expiry on Get catches gaps between sweeps.
type TTLMap[K comparable, V any] struct {
	mu         sync.RWMutex
	items      map[K]entry[V]
	opts       Options
	closeCh    chan struct{}
	closeOnce  sync.Once
}

// New constructs a TTLMap and starts its background sweep goroutine. The
// goroutine exits when ctx is cancelled or Close is called.
func New[K comparable, V any](ctx context.Context, opts Options) *TTLMap[K, V] {
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = defaultSweepInterval
	}

	m := &TTLMap[K, V]{
		items:   make(map[K]entry[V]),
		opts:    opts,
		closeCh: make(chan struct{}),
	}

	go m.sweep(ctx)
	return m
}

// Set inserts or updates key with the given value and TTL. If MaxEntries is
// set and the map is at capacity, the entry with the oldest insertedAt is
// evicted before the new entry is stored.
func (m *TTLMap[K, V]) Set(key K, value V, ttl time.Duration) {
	now := time.Now()
	e := entry[V]{
		value:      value,
		expiresAt:  now.Add(ttl),
		insertedAt: now,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// If key already exists, update in place — no eviction needed.
	if _, exists := m.items[key]; !exists && m.opts.MaxEntries > 0 {
		// Evict until we have room.
		for len(m.items) >= m.opts.MaxEntries {
			m.evictOldest()
		}
	}

	m.items[key] = e
}

// evictOldest removes the entry whose insertedAt is earliest. Must be called
// with m.mu held for write.
func (m *TTLMap[K, V]) evictOldest() {
	var (
		oldestKey K
		oldestAt  time.Time
		first     = true
	)

	for k, e := range m.items {
		if first || e.insertedAt.Before(oldestAt) {
			oldestKey = k
			oldestAt = e.insertedAt
			first = false
		}
	}

	if !first {
		delete(m.items, oldestKey)
	}
}

// Get returns the value for key and true if the entry exists and has not
// expired. Returns the zero value and false otherwise.
func (m *TTLMap[K, V]) Get(key K) (V, bool) {
	m.mu.RLock()
	e, ok := m.items[key]
	m.mu.RUnlock()

	if !ok || time.Now().After(e.expiresAt) {
		var zero V
		return zero, false
	}

	return e.value, true
}

// Delete removes the entry for key, if present.
func (m *TTLMap[K, V]) Delete(key K) {
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
}

// Clear removes all entries.
func (m *TTLMap[K, V]) Clear() {
	m.mu.Lock()
	m.items = make(map[K]entry[V])
	m.mu.Unlock()
}

// Len returns the count of entries that have not yet expired. It performs a
// full scan under a read lock, so prefer not calling it on hot paths.
func (m *TTLMap[K, V]) Len() int {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, e := range m.items {
		if !now.After(e.expiresAt) {
			count++
		}
	}

	return count
}

// Close stops the background sweep goroutine. Safe to call multiple times.
// The map remains usable for reads and writes after Close; only background
// sweeping stops.
func (m *TTLMap[K, V]) Close() {
	m.closeOnce.Do(func() {
		close(m.closeCh)
	})
}

// sweep is the background goroutine that deletes expired entries on a ticker.
func (m *TTLMap[K, V]) sweep(ctx context.Context) {
	ticker := time.NewTicker(m.opts.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.removeExpired()
		case <-ctx.Done():
			return
		case <-m.closeCh:
			return
		}
	}
}

// removeExpired deletes all entries whose TTL has elapsed.
func (m *TTLMap[K, V]) removeExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, e := range m.items {
		if now.After(e.expiresAt) {
			delete(m.items, k)
		}
	}
}
