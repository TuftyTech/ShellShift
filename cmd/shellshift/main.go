// Command shellshift collects public proxy configurations, proves that each one
// actually carries traffic, and publishes the survivors.
//
// The binary is the whole system: there is no companion interpreter, no sidecar
// process, and no configuration read at import time. Every subcommand is a pure
// function of its flags and the files it is pointed at.
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time: -ldflags "-X main.version=$(git describe --tags)".
var version = "dev"

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

func main() {
	cmds := []command{
		{"run", "collect, verify and publish one full cycle", runRun},
		{"site", "render the static site from a published network.json", runSite},
		{"decode", "decode proxy URIs from stdin and report what was rejected", runDecode},
		{"doctor", "establish the positive controls a diagnosis needs (INV-55)", runDoctor},
		{"version", "print the build version", printVersion},
	}

	if len(os.Args) < 2 {
		usage(cmds)
		os.Exit(2)
	}

	name := os.Args[1]
	for _, c := range cmds {
		if c.name == name {
			if err := c.run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "shellshift %s: %v\n", name, err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "shellshift: unknown subcommand %q\n\n", name)
	usage(cmds)
	os.Exit(2)
}

func usage(cmds []command) {
	fmt.Fprintf(os.Stderr, "shellshift %s\n\nusage: shellshift <command> [flags]\n\n", version)
	for _, c := range cmds {
		fmt.Fprintf(os.Stderr, "  %-9s %s\n", c.name, c.summary)
	}
}

func printVersion([]string) error {
	fmt.Println(version)
	return nil
}
