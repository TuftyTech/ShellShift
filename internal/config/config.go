// Package config loads the run configuration.
//
// Loading is explicit and happens where a caller asks for it. Nothing is read at import
// time and nothing calls os.Exit: the predecessor executed CONFIG = load_settings() at
// module scope, so importing any part of the project read a file from disk and a typo in
// the YAML killed every entry point identically, with a print to stderr as the only
// diagnostic.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Config is the whole run configuration.
type Config struct {
	// Sources is the feed list. It is public configuration in the repository, not a
	// secret: the predecessor stored it as a repository secret while committing all 118
	// entries to a public repository, which is the worst of both arrangements.
	Sources []string `json:"sources"`

	// WhitelistDomains and WhitelistNetworks are the censor whitelist feeds that decide the
	// whitelisted class. Both are optional; without them nothing is classified and the run
	// says so rather than silently publishing an empty class.
	WhitelistDomains  []string `json:"whitelist_domains,omitempty"`
	WhitelistNetworks []string `json:"whitelist_networks,omitempty"`

	// Concurrency bounds simultaneous verifications. Zero means derive it.
	//
	// Most of what this governs is waiting on TCP timeouts to distinct nodes, which shares
	// nothing, so it can be large. See ProofConcurrency for the part that cannot.
	Concurrency int `json:"concurrency,omitempty"`

	// ProofConcurrency bounds simultaneous proofs. Zero means derive it from Concurrency.
	//
	// This is the limit that matters for behaving well. Reach dials a distinct node per
	// candidate; proof goes through a tunnel to a handful of shared endpoints, and pointing
	// hundreds of simultaneous requests at three providers is what makes them refuse us and
	// makes working nodes look dead (INV-53). Modelled at 100k candidates, one shared limit
	// forces a choice between a reach stage that wastes six minutes on timeouts and a proof
	// stage that floods the providers; two limits remove the choice.
	ProofConcurrency int `json:"proof_concurrency,omitempty"`

	// GeoIP disables country lookup when false. It is a third-party service over plaintext,
	// so it is opt-in and its answer is treated as decoration, never as a security input.
	GeoIP bool `json:"geoip,omitempty"`

	// MeasureThroughput disables the download pass when false. Measurement is a ranking
	// signal and costs real bandwidth, so it is a choice rather than an assumption.
	MeasureThroughput bool `json:"measure_throughput,omitempty"`

	// SiteURL is the published origin, used to render subscription links.
	SiteURL string `json:"site_url,omitempty"`

	// RunBudget is the wall-clock ceiling for a whole run.
	RunBudget Duration `json:"run_budget,omitempty"`
}

// Duration is a time.Duration that reads as a string in JSON, so the configuration says
// "8m" rather than a count of nanoseconds nobody can check by eye.
type Duration time.Duration

// UnmarshalJSON parses a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: %q is not a duration: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON writes the duration back as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Load reads and validates a configuration. The environment is not consulted; use
// LoadWithEnv or LoadFile for that.
func Load(r io.Reader) (Config, error) {
	return LoadWithEnv(r, func(string) (string, bool) { return "", false })
}

// Environment overrides, applied after the file and before validation.
//
// They exist so an operator can keep a curated feed list out of a public tree — in Actions, as
// a repository secret handed to the run as an environment variable — without that list also
// being committed. The distinction from the predecessor matters and is the reason this is an
// override rather than a replacement for the file: it held the list in a repository secret
// while all 118 entries sat in the public tree, so the secret protected nothing and there were
// two places to forget to update. Here the repository carries a public default and the secret,
// when present, replaces it. Putting the same URLs in both is the arrangement to avoid.
//
// One entry per line; blank lines and #-comments are ignored. Lines rather than JSON because
// Actions masks a multi-line secret line by line, so a feed URL cannot surface in a log even
// though the run prints per-feed yield.
const (
	EnvSources           = "SHELLSHIFT_SOURCES"
	EnvWhitelistDomains  = "SHELLSHIFT_WHITELIST_DOMAINS"
	EnvWhitelistNetworks = "SHELLSHIFT_WHITELIST_NETWORKS"
)

// LoadWithEnv reads a configuration and lets the environment replace its lists before
// validation. See EnvSources for what the mechanism is for.
func LoadWithEnv(r io.Reader, lookup func(string) (string, bool)) (Config, error) {
	var c Config
	dec := json.NewDecoder(r)
	// An unknown field is an error rather than a silent no-op. The predecessor carried a
	// whole block of settings that nothing read — a thread count and a user-agent that
	// looked like tuning knobs and did nothing at all.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if err := c.applyEnv(lookup); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// applyEnv replaces a list wholesale when its variable is present.
//
// Replacement rather than a merge: an operator who supplies a list means that list, and
// merging would silently keep feeds they had removed.
//
// A variable that is present but lists nothing is an error rather than a fall back to the
// file. That case is a misconfigured secret, and falling back would run the committed list
// while the operator believed their private one was in use. Publishing from the wrong list
// without saying so is worse than refusing to start.
func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	for _, override := range []struct {
		name string
		dst  *[]string
	}{
		{EnvSources, &c.Sources},
		{EnvWhitelistDomains, &c.WhitelistDomains},
		{EnvWhitelistNetworks, &c.WhitelistNetworks},
	} {
		raw, ok := lookup(override.name)
		if !ok {
			continue
		}
		list := envList(raw)
		if len(list) == 0 {
			return fmt.Errorf("config: %s is set but lists nothing", override.name)
		}
		*override.dst = list
	}
	return nil
}

// envList reads one entry per line, ignoring blank lines and #-comments.
func envList(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// LoadFile reads a configuration from disk, with the environment able to replace its lists.
func LoadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	return LoadWithEnv(f, os.LookupEnv)
}

// Validate rejects a configuration that cannot produce a run.
func (c Config) Validate() error {
	if len(c.Sources) == 0 {
		return fmt.Errorf("config: no sources")
	}
	seen := map[string]bool{}
	for i, s := range c.Sources {
		if !strings.HasPrefix(s, "https://") {
			return fmt.Errorf("config: source %d is not https: %q", i, s)
		}
		if seen[s] {
			return fmt.Errorf("config: source %d is a duplicate: %q", i, s)
		}
		seen[s] = true
	}
	// The whitelist decides which nodes carry the project central claim, so its feeds are held
	// to the same transport requirement as everything else.
	for _, group := range [][]string{c.WhitelistDomains, c.WhitelistNetworks} {
		for i, s := range group {
			if !strings.HasPrefix(s, "https://") {
				return fmt.Errorf("config: whitelist feed %d is not https: %q", i, s)
			}
		}
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("config: negative concurrency")
	}
	if c.ProofConcurrency < 0 {
		return fmt.Errorf("config: negative proof concurrency")
	}
	// A proof limit above the verification limit cannot take effect and says the opposite of what
	// it means, so it is a configuration error rather than something to silently clamp.
	if c.Concurrency > 0 && c.ProofConcurrency > c.Concurrency {
		return fmt.Errorf("config: proof_concurrency (%d) exceeds concurrency (%d), which cannot "+
			"take effect: no more proofs can run than verifications",
			c.ProofConcurrency, c.Concurrency)
	}
	return nil
}

// ProofLimit is how many proofs may run at once.
//
// Derived rather than defaulted to the verification limit, because the two govern different
// resources and the derived value is the one that behaves: a quarter of the verification limit
// keeps the reach stage wide while holding the request rate at the shared endpoints to something
// they tolerate. Measured at concurrency 256 against 24 on the same feed, the proof pass rate
// differed by roughly a factor of two (INV-53).
func (c Config) ProofLimit() int {
	if c.ProofConcurrency > 0 {
		return c.ProofConcurrency
	}
	if c.Concurrency > 0 {
		if n := c.Concurrency / 4; n > 0 {
			return n
		}
		return 1
	}
	return 0
}
