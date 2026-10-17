package config

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadReadsDurationsAsWords(t *testing.T) {
	c, err := Load(strings.NewReader(`{"sources":["https://a.example.com/f.txt"],"run_budget":"8m"}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.RunBudget.Duration() != 8*time.Minute {
		t.Fatalf("run budget = %v, want 8m", c.RunBudget.Duration())
	}
}

// An unknown field is an error rather than a silent no-op. The predecessor carried a whole
// block of settings that nothing read — a thread count and a user-agent that looked like
// tuning knobs and did nothing at all.
func TestUnknownFieldsAreRejected(t *testing.T) {
	_, err := Load(strings.NewReader(`{"sources":["https://a.example.com/f.txt"],"threads":25}`))
	if err == nil {
		t.Fatal("an unknown field must be an error, not a no-op")
	}
}

func TestValidationRejectsUnusableConfigs(t *testing.T) {
	cases := []struct{ name, body string }{
		{"no sources", `{"sources":[]}`},
		{"plaintext source", `{"sources":["http://a.example.com/f.txt"]}`},
		{"duplicate source", `{"sources":["https://a.example.com/f.txt","https://a.example.com/f.txt"]}`},
		{"negative concurrency", `{"sources":["https://a.example.com/f.txt"],"concurrency":-1}`},
		{"unparseable duration", `{"sources":["https://a.example.com/f.txt"],"run_budget":"soon"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(tc.body)); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// Loading is explicit and nothing happens at import time. The predecessor executed its
// loader at module scope, so importing any part of the project read a file from disk and a
// typo in the configuration called os.Exit.
func TestLoadingIsExplicit(t *testing.T) {
	if _, err := LoadFile("does-not-exist.json"); err == nil {
		t.Fatal("a missing file must return an error rather than exiting the process")
	}
}

// The example configuration carries no feed list, and that is the point of it.
//
// It used to ship one entry — an example.com-shaped raw.githubusercontent.com URL — to show the
// key existed. In a public tree a line that looks like a feed is a line somebody copies, and the
// shape of a feed URL is the one thing about this project worth keeping out of the tree: the
// predecessor put its whole 118-entry list in a public repository while also holding it in a
// repository secret, so the secret protected nothing.
//
// So the file is a template, not a runnable configuration, and this holds both halves of that:
// without the operator's list it must refuse to load, and with the list supplied the documented
// way it must be complete and valid.
func TestExampleConfigCarriesNoFeedListAndIsOtherwiseComplete(t *testing.T) {
	const path = "../../config/sources.example.json"

	if _, err := LoadFile(path); err == nil {
		t.Fatal("the example configuration loaded without a feed list; it must not carry one")
	} else if !strings.Contains(err.Error(), "no sources") {
		t.Fatalf("the example must fail only for the missing list, got: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	// Everything else in the file has to be right, or "it does not load" stops meaning
	// "the list is absent" and starts hiding a typo in a field the operator does read.
	c, err := LoadWithEnv(bytes.NewReader(raw), func(k string) (string, bool) {
		if k == EnvSources {
			return "https://private.example.com/feed.txt", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("the example plus a supplied list must be a valid configuration: %v", err)
	}
	if len(c.Sources) != 1 {
		t.Fatalf("the supplied list did not reach the configuration: %d sources", len(c.Sources))
	}
	if len(c.WhitelistDomains) == 0 || len(c.WhitelistNetworks) == 0 {
		t.Error("the example must still show the whitelist feeds: those are public lists")
	}
}

// The override exists so a curated feed list can stay out of a public tree. It replaces the
// file's list rather than merging into it: an operator who supplies a list means that list, and
// a merge would silently keep feeds they had removed.
func TestEnvironmentReplacesTheLists(t *testing.T) {
	const body = `{"sources":["https://committed.example.com/f.txt"],
	               "whitelist_domains":["https://committed.example.com/wl.txt"]}`

	env := map[string]string{
		EnvSources: "https://private.example.com/a.txt\n" +
			"# a comment, and a blank line follow\n\n" +
			"  https://private.example.com/b.txt  \n",
		EnvWhitelistNetworks: "https://private.example.com/cidr.txt",
	}
	c, err := LoadWithEnv(strings.NewReader(body), func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	want := []string{"https://private.example.com/a.txt", "https://private.example.com/b.txt"}
	if len(c.Sources) != len(want) {
		t.Fatalf("sources = %v, want %v", c.Sources, want)
	}
	for i := range want {
		if c.Sources[i] != want[i] {
			t.Errorf("source %d = %q, want %q", i, c.Sources[i], want[i])
		}
	}
	// An untouched list keeps the file's value; a set one replaces it.
	if len(c.WhitelistDomains) != 1 || c.WhitelistDomains[0] != "https://committed.example.com/wl.txt" {
		t.Errorf("whitelist domains should come from the file: %v", c.WhitelistDomains)
	}
	if len(c.WhitelistNetworks) != 1 {
		t.Errorf("whitelist networks should come from the environment: %v", c.WhitelistNetworks)
	}
}

// A secret that is set but lists nothing is a misconfiguration. Falling back to the committed
// list there would run the wrong feeds while the operator believed their private ones were in
// use, and publish the result without saying so.
func TestAnEmptyOverrideIsAnErrorNotAFallback(t *testing.T) {
	const body = `{"sources":["https://committed.example.com/f.txt"]}`
	for _, raw := range []string{"", "   ", "\n\n", "# only a comment\n"} {
		_, err := LoadWithEnv(strings.NewReader(body), func(k string) (string, bool) {
			if k == EnvSources {
				return raw, true
			}
			return "", false
		})
		if err == nil {
			t.Errorf("%q was accepted as an override", raw)
		}
	}
}

// Overridden values go through the same validation as the file's. A secret is not a way past
// the https requirement.
func TestOverriddenSourcesAreStillValidated(t *testing.T) {
	const body = `{"sources":["https://committed.example.com/f.txt"]}`
	_, err := LoadWithEnv(strings.NewReader(body), func(k string) (string, bool) {
		if k == EnvSources {
			return "http://plaintext.example.com/f.txt", true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("a plaintext source from the environment must be refused")
	}
}

// Load itself must not read the process environment: a test or a caller asking for exactly
// what a file says has to get that.
func TestLoadIgnoresTheEnvironment(t *testing.T) {
	t.Setenv(EnvSources, "https://leaked.example.com/f.txt")
	c, err := Load(strings.NewReader(`{"sources":["https://committed.example.com/f.txt"]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Sources[0] != "https://committed.example.com/f.txt" {
		t.Fatalf("Load consulted the environment: %v", c.Sources)
	}
}
