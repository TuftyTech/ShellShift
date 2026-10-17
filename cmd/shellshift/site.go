package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tuftytech/shellshift/internal/publish"
)

// runSite renders the static site from a published payload.
//
// It is a separate subcommand from run because rendering must be repeatable without
// re-verifying anything: a copy change should not cost an hour of network work, and a
// template regression should be reproducible from a fixture.
func runSite(args []string) error {
	fs := flag.NewFlagSet("site", flag.ContinueOnError)
	dataPath := fs.String("data", "dist/network.json", "published payload to render from")
	outDir := fs.String("out", "dist", "directory to write the site into")
	origin := fs.String("origin", "", "published origin for subscription links")
	at := fs.String("at", "", "render as though it were this RFC3339 time; empty means now")
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := os.ReadFile(*dataPath)
	if err != nil {
		return fmt.Errorf("site: %w", err)
	}
	var data publish.Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("site: reading %s: %w", *dataPath, err)
	}
	if data.Version != publish.DataVersion {
		return fmt.Errorf("site: payload version %d, this binary renders %d",
			data.Version, publish.DataVersion)
	}

	now := time.Now()
	if *at != "" {
		parsed, perr := time.Parse(time.RFC3339, *at)
		if perr != nil {
			return fmt.Errorf("site: %w", perr)
		}
		now = parsed
	}

	site := publish.BuildSiteData(data, *origin, now)

	// Both languages are in each document and the control swaps an attribute, so the pair
	// below is not "the Russian page and the English one": it is one page and a no-JavaScript
	// fallback. The root defaults to Russian, the copy one level down defaults to English, and
	// the language links point at each other so switching still works with the script blocked.
	pages := map[string]string{
		"ru": filepath.Join(*outDir, "index.html"),
		"en": filepath.Join(*outDir, "en", "index.html"),
	}
	for lang, path := range pages {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		f, cerr := os.Create(path)
		if cerr != nil {
			return cerr
		}
		langSite := site
		if lang == "en" {
			// The fallback page is one directory deeper, so every asset link has to climb.
			// Getting this wrong is how a translated page ships unstyled.
			langSite.AssetBase = "../"
		}
		if rerr := publish.RenderSite(f, langSite, lang); rerr != nil {
			f.Close()
			return rerr
		}
		f.Close()
	}

	// Assets are copied rather than referenced from the module cache, so the output
	// directory is a complete site that can be served by anything.
	//
	// Once, and only at the root: the fallback page climbs to them with AssetBase. They used to
	// be written into both directories, which was invisible while they were two text files and
	// stopped being invisible when one of them became a 70 KB illustration.
	for _, name := range publish.AssetNames() {
		body, aerr := publish.Asset(name)
		if aerr != nil {
			return aerr
		}
		dst := filepath.Join(*outDir, name)
		if merr := os.MkdirAll(filepath.Dir(dst), 0o755); merr != nil {
			return merr
		}
		if werr := os.WriteFile(dst, body, 0o644); werr != nil {
			return werr
		}
	}

	fmt.Printf("rendered %d pages and %d assets into %s\n",
		len(pages), len(publish.AssetNames()), *outDir)
	return nil
}
