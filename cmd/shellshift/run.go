package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tuftytech/shellshift/internal/config"
	"github.com/tuftytech/shellshift/internal/intake"
	"github.com/tuftytech/shellshift/internal/ledger"
	"github.com/tuftytech/shellshift/internal/pipeline"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/publish"
	"github.com/tuftytech/shellshift/internal/tunnel"
	"github.com/tuftytech/shellshift/internal/verify"
)

// engineVersion names the tunnel implementation in published output, so a visitor can see
// what actually did the work rather than a slogan.
const engineVersion = "sing-box/1.13.19 (in-process)"

func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "config/sources.json", "path to the configuration")
	statePath := fs.String("state", "", "path to the ledger snapshot; empty starts fresh")
	outDir := fs.String("out", "dist", "directory to write published artifacts into")
	dryRun := fs.Bool("dry-run", false, "verify and report, but write nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// INV-49. A binary built without the uTLS tag silently drops every Reality node, which
	// in the observed corpus is sixty-two percent of the catalogue, and the run still looks
	// successful. So the check is first and it is fatal.
	if err := tunnel.CheckBuild(); err != nil {
		return err
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}

	nodes, sources := loadState(*statePath)

	dialer := tunnel.NewInProcess(tunnel.Config{})
	defer dialer.Close()

	fetcher := intake.NewFetcher(intake.DefaultLimits())

	// One resolver for the whole run, shared by verification, masking and geography. Resolving
	// per node independently is duplicated work — half of it, measured on a live feed — and at
	// high concurrency it also turns the verifier into a load generator against its own
	// resolver.
	resolver := policy.NewCachingResolver(policy.NewResolver(), 5*time.Minute)

	engine := verify.New(dialer, verify.NewProver())
	engine.Resolver = resolver
	// Reach and proof are bounded separately: the first shares nothing between nodes, the second
	// shares a handful of third-party endpoints (INV-53).
	engine.LimitProofs(cfg.ProofLimit())
	if cfg.MeasureThroughput {
		engine.Meter = verify.NewMeter()
	}

	ctx := context.Background()

	// The whitelist decides the class that carries the project central claim, so its absence is
	// reported rather than left to look like a class nobody qualified for.
	whitelist, problems := pipeline.LoadWhitelist(ctx, fetcher, cfg.WhitelistDomains, cfg.WhitelistNetworks)
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "whitelist: %s\n", p)
	}
	d, l, n := whitelist.Counts()
	fmt.Printf("whitelist: %d domains, %d literals, %d networks\n\n", d, l, n)

	runner := &pipeline.Runner{
		Config:     cfg,
		Fetcher:    fetcher,
		Engine:     engine,
		Nodes:      nodes,
		Sources:    sources,
		Resolver:   resolver,
		Classifier: policy.NewClassifier(whitelist, policy.NewMaskingProver(resolver)),
	}
	if cfg.GeoIP {
		runner.Geo = policy.NewGeoLocator()
	}

	res, err := runner.Run(ctx)
	if err != nil && len(res.Entries) == 0 {
		return err
	}

	report(res, runner)

	if *dryRun {
		fmt.Println("\ndry run: nothing written")
		return nil
	}
	return writeArtifacts(*outDir, *statePath, res, nodes, sources)
}

// loadState reads the ledger, treating an absent file as an empty ledger and an unreadable
// one as fatal.
//
// The distinction matters. A first run legitimately has no state. A corrupt or
// wrong-version snapshot is a different situation, and continuing from an empty ledger
// there would silently discard every reputation record and re-verify the whole catalogue as
// though it were new.
func loadState(path string) (*ledger.Ledger, *ledger.Sources) {
	nodes := ledger.New(ledger.DefaultPolicy())
	sources := ledger.NewSources(ledger.DefaultSourcePolicy())
	if path == "" {
		return nodes, sources
	}

	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "state: %v (starting fresh)\n", err)
		}
		return nodes, sources
	}
	defer f.Close()

	loaded, err := ledger.Load(f, ledger.DefaultPolicy())
	if err != nil {
		fmt.Fprintf(os.Stderr, "state: %v (starting fresh)\n", err)
		return nodes, sources
	}
	return loaded, sources
}

func report(res pipeline.Result, runner *pipeline.Runner) {
	f := res.Funnel
	fmt.Printf("run finished in %s\n\n", res.Elapsed.Round(time.Millisecond))
	fmt.Printf("  feeds        %d fetched, %d failed, %d mirrored\n",
		res.FeedsFetched, res.FeedsFailed, res.MirroredFeeds)
	fmt.Printf("  collected    %d\n", f.Collected)
	fmt.Printf("  decoded      %d  (%d rejected)\n", f.Decoded, f.Rejected)
	fmt.Printf("  candidates   %d  (%d duplicates across feeds)\n", f.Candidates, f.Duplicates)
	fmt.Printf("  policy       %d\n", f.Policy)
	fmt.Printf("  reached      %d\n", f.Reached)
	fmt.Printf("  proven       %d  (%d failed)\n", f.Proven, f.Failed)
	if res.SkippedInBackoff > 0 {
		fmt.Printf("  in backoff   %d  (not re-verified this run)\n", res.SkippedInBackoff)
	}
	if f.NotAttempted > 0 {
		fmt.Printf("  not tried    %d  (budget ran out)\n", f.NotAttempted)
	}
	// The accounting invariant, printed whether or not it holds. A number that only appears
	// when it is wrong is a number nobody trusts when it is right (INV-40).
	if n := f.Unaccounted(); n != 0 {
		fmt.Fprintf(os.Stderr, "\n  ACCOUNTING  %+d lines reached no bucket — "+
			"collected != rejected+duplicates+deferred+not-tried+failed+proven (INV-40)\n", n)
	} else {
		fmt.Printf("  accounting   balanced\n")
	}

	if len(res.Rejections) > 0 {
		fmt.Printf("\nrejections by reason\n")
		for _, k := range sortedByCount(res.Rejections) {
			fmt.Printf("  %-42s %d\n", k, res.Rejections[k])
		}
	}

	if len(res.StageFailures) > 0 {
		fmt.Printf("\nwhy nodes failed\n")
		for _, k := range sortedByCount(res.StageFailures) {
			fmt.Printf("  %-48s %d\n", k, res.StageFailures[k])
		}
	}

	if len(res.ClassReasons) > 0 {
		fmt.Printf("\nclass: %d whitelisted\n", res.Classified)
		for _, k := range sortedByCount(res.ClassReasons) {
			fmt.Printf("  %-42s %d\n", k, res.ClassReasons[k])
		}
	}
	if res.GeoResolved > 0 {
		fmt.Printf("\ncountries resolved for %d nodes\n", res.GeoResolved)
	}

	if ranked := runner.Sources.Ranked(); len(ranked) > 0 {
		fmt.Printf("\ntop feeds by yield\n")
		for i, st := range ranked {
			if i >= 5 {
				break
			}
			fmt.Printf("  %5.2f%%  %6d proven of %7d  %s\n",
				st.Yield()*100, st.Proven, st.Offered, st.URL)
		}
	}
}

func writeArtifacts(outDir, statePath string, res pipeline.Result,
	nodes *ledger.Ledger, sources *ledger.Sources) error {

	// The guard stands between assembling a result and letting it replace what is live.
	// A run in which everything failed must not publish its emptiness (INV-43).
	previous := previousCount(outDir)
	if err := publish.DefaultGuard().Check(len(res.Entries), previous); err != nil {
		return fmt.Errorf("refusing to publish: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	// Codes are assigned across the whole published set at once, because uniqueness is a property
	// of the set and not of a node: the length is whatever this set needs.
	codes := publish.ShortCodes(res.Entries)
	label := func(e publish.Entry) string {
		return publish.Label(e.Node, codes[e.Node.Key()])
	}

	for _, b := range publish.Bundles() {
		body, err := publish.Render(b, res.Entries, label)
		if err != nil {
			return fmt.Errorf("rendering %s: %w", b.Name, err)
		}
		if err := writeFile(filepath.Join(outDir, b.Name), []byte(body)); err != nil {
			return err
		}
	}

	data := publish.BuildData(res.Entries, res.Funnel, time.Now(), res.Elapsed,
		engineVersion, publish.Extras{
			Rejections:   res.Rejections,
			Streaks:      res.Streaks,
			ClassReasons: res.ClassReasons,
			History:      res.History,
			Covers:       res.Covers,
		})
	var dataBuf []byte
	{
		f, err := os.CreateTemp(outDir, "data-*.json")
		if err != nil {
			return err
		}
		name := f.Name()
		if err := publish.WriteData(f, data); err != nil {
			f.Close()
			os.Remove(name)
			return err
		}
		f.Close()
		dataBuf, err = os.ReadFile(name)
		os.Remove(name)
		if err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(outDir, "network.json"), dataBuf); err != nil {
		return err
	}

	byFailures, byAge := nodes.Prune()
	if statePath != "" {
		if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
			return err
		}
		f, err := os.Create(statePath)
		if err != nil {
			return err
		}
		if err := nodes.Save(f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	fmt.Printf("\nwrote %d bundles and network.json to %s\n", len(publish.Bundles()), outDir)
	fmt.Printf("ledger: %d entries (pruned %d for failures, %d for age)\n",
		nodes.Len(), byFailures, byAge)
	return nil
}

// previousCount reads how many nodes the last publication contained, so the guard has
// something to compare against.
func previousCount(outDir string) int {
	raw, err := os.ReadFile(filepath.Join(outDir, "network.json"))
	if err != nil {
		return 0
	}
	var d struct {
		Funnel struct{ Proven int } `json:"funnel"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return 0
	}
	return d.Funnel.Proven
}

func writeFile(path string, body []byte) error {
	return os.WriteFile(path, body, 0o644)
}
