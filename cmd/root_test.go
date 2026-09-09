package cmd

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
)

func TestCachedConfigReusesConfigForSameSource(t *testing.T) {
	previousCache := configCache
	t.Cleanup(func() { configCache = previousCache })
	configCache = make(map[string]*config.Config)

	loads := 0
	load := func() *config.Config {
		loads++
		return &config.Config{}
	}

	first := cachedConfig("file:config.toml", load)
	second := cachedConfig("file:config.toml", load)
	third := cachedConfig("file:other.toml", load)

	if first != second {
		t.Fatal("expected identical config sources to reuse the cached config")
	}
	if first == third {
		t.Fatal("expected different config sources to use different configs")
	}
	if loads != 2 {
		t.Fatalf("loaded %d configs, want 2", loads)
	}
}

func TestCachedConfigDoesNotPersistWithoutInvocationCache(t *testing.T) {
	previousCache := configCache
	t.Cleanup(func() { configCache = previousCache })
	configCache = nil

	loads := 0
	load := func() *config.Config {
		loads++
		return &config.Config{}
	}

	first := cachedConfig("default", load)
	second := cachedConfig("default", load)

	if first == second {
		t.Fatal("expected configs not to be cached outside an invocation")
	}
	if loads != 2 {
		t.Fatalf("loaded %d configs, want 2", loads)
	}
}
