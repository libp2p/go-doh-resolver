package doh

import (
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

// TestCacheConcurrent hammers the cache from many goroutines with near-instant
// TTLs so reads constantly hit the expired-entry delete path while writes and
// other deletes run concurrently. It guards against the data race that map
// deletion under a read lock would cause; run with -race.
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
				} else {
					c.get(k)
				}
			}
		})
	}
	wg.Wait()
}
