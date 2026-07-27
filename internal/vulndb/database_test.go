package vulndb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type failingSource struct{}

func (f failingSource) Name() string { return "failing" }
func (f failingSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	return nil, fmt.Errorf("upstream down")
}

func TestQueryDoesNotCacheSourceFailures(t *testing.T) {
	cache := NewMemoryCache()
	client, err := NewClient(WithSources(failingSource{}), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Query(context.Background(), "npm", "lodash", "4.17.20")
	if err == nil {
		t.Fatal("expected query error when all sources fail")
	}

	if _, err := cache.Get("npm:lodash:4.17.20"); err == nil {
		t.Fatal("failed lookups must not be cached as empty results")
	}
}

func TestMemoryCacheCopiesSlices(t *testing.T) {
	cache := NewMemoryCache().(*memoryCache)
	vulns := []Vulnerability{{ID: "V1"}}
	if err := cache.Set("k", vulns, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	got[0].ID = "mutated"
	again, err := cache.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].ID != "V1" {
		t.Fatalf("cache exposed mutable slice, got %s", again[0].ID)
	}
}
