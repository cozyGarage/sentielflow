package vulndb

import (
	"fmt"
	"sync"
	"time"
)

type cacheEntry struct {
	vulns     []Vulnerability
	expiresAt time.Time
}

type memoryCache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

// NewMemoryCache creates an in-memory vulnerability cache.
func NewMemoryCache() Cache {
	return &memoryCache{
		items: make(map[string]cacheEntry),
	}
}

func (c *memoryCache) Get(key string) ([]Vulnerability, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.items[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, fmt.Errorf("cache miss")
	}

	return entry.vulns, nil
}

func (c *memoryCache) Set(key string, vulns []Vulnerability, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheEntry{
		vulns:     vulns,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

func (c *memoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]cacheEntry)
	return nil
}
