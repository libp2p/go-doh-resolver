package doh

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestCacheExpiry checks that a fresh entry is a hit, an expired entry is a
// miss, and reading an expired entry deletes it from the map. The fake clock
// from synctest advances past the TTL without a real sleep.
func TestCacheExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newCache[int]()
		c.set("k", 42, time.Second)

		if v, ok := c.get("k"); !ok || v != 42 {
			t.Fatalf("expected fresh hit (42, true), got (%d, %t)", v, ok)
		}

		time.Sleep(time.Second + time.Millisecond)

		if v, ok := c.get("k"); ok || v != 0 {
			t.Fatalf("expected miss after expiry (0, false), got (%d, %t)", v, ok)
		}
		if len(c.entries) != 0 {
			t.Fatalf("expected expired entry to be deleted, %d remain", len(c.entries))
		}
	})
}

// TestCacheZeroTTL checks that a zero TTL is a no-op, so a disabled cache stays
// empty.
func TestCacheZeroTTL(t *testing.T) {
	c := newCache[int]()
	c.set("k", 42, 0)

	// Check the map before any get. A get would report a miss for an entry that
	// was stored and then evicted on read, so only the map state right after set
	// proves that set stored nothing.
	if len(c.entries) != 0 {
		t.Fatalf("expected zero-TTL set to store nothing, got %d entries", len(c.entries))
	}
	if _, ok := c.get("k"); ok {
		t.Fatal("expected zero-TTL set to be a no-op")
	}
}

// TestCacheRefreshNotClobbered checks the guarantee that justifies the double-
// checked locking in get: when a set refreshes an entry in the window after get
// drops the read lock on an expired entry but before it takes the write lock,
// get must return the refreshed value rather than delete it. The afterExpiredRead
// seam drives the set into that exact window, so the result does not depend on
// goroutine scheduling. Remove the re-check in get and this test fails.
func TestCacheRefreshNotClobbered(t *testing.T) {
	c := newCache[int]()
	// Seed an already-expired entry so get's first read sees it as expired and
	// heads for the write-locked delete. set cannot do this: it always stores a
	// future expiry.
	c.entries["k"] = cacheEntry[int]{val: 1, expire: time.Now().Add(-time.Second)}

	c.afterExpiredRead = func() {
		c.afterExpiredRead = nil // refresh exactly once
		c.set("k", 2, time.Minute)
	}

	if v, ok := c.get("k"); !ok || v != 2 {
		t.Fatalf("expected refreshed hit (2, true), got (%d, %t)", v, ok)
	}
	if len(c.entries) != 1 {
		t.Fatalf("expected refreshed entry to survive, %d entries", len(c.entries))
	}
}

// TestCacheDeletedDuringExpiredGet checks the other re-check branch: when
// another get deletes the expired entry in the same window, the re-checking get
// finds it gone and reports a clean miss instead of touching the map again.
func TestCacheDeletedDuringExpiredGet(t *testing.T) {
	c := newCache[int]()
	c.entries["k"] = cacheEntry[int]{val: 1, expire: time.Now().Add(-time.Second)}

	c.afterExpiredRead = func() {
		c.afterExpiredRead = nil
		c.mx.Lock()
		delete(c.entries, "k")
		c.mx.Unlock()
	}

	if v, ok := c.get("k"); ok || v != 0 {
		t.Fatalf("expected miss after concurrent delete (0, false), got (%d, %t)", v, ok)
	}
	if len(c.entries) != 0 {
		t.Fatalf("expected empty cache, %d entries", len(c.entries))
	}
}

// TestCacheConcurrent hammers the cache from many goroutines with near-instant
// TTLs so reads constantly hit the expired-entry delete path while writes and
// other deletes run concurrently. Run with -race: it guards against the data
// race that map deletion under a read lock would cause. The assertions add a
// second check, that no read ever returns a value that was not stored and that
// the map never holds a stray key or value.
func TestCacheConcurrent(t *testing.T) {
	c := newCache[int]()
	keys := []string{"a", "b", "c", "d"}

	const workers = 64
	const iters = 1000

	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range iters {
				k := keys[(w+i)%len(keys)]
				if i%2 == 0 {
					c.set(k, i, time.Nanosecond)
				} else if v, ok := c.get(k); ok && (v < 0 || v >= iters) {
					// A hit must return an iteration index some set call stored.
					t.Errorf("get(%q) returned out-of-range value %d", k, v)
				}
			}
		})
	}
	wg.Wait()

	c.mx.RLock()
	defer c.mx.RUnlock()
	if len(c.entries) > len(keys) {
		t.Errorf("cache holds %d entries, want at most %d", len(c.entries), len(keys))
	}
	for k, e := range c.entries {
		if !slices.Contains(keys, k) {
			t.Errorf("cache holds unexpected key %q", k)
		}
		if e.val < 0 || e.val >= iters {
			t.Errorf("cache holds out-of-range value %d for key %q", e.val, k)
		}
	}
}
