// Command iroh-relay runs a small iroh relay server.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/tmc/go-iroh/relayserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "iroh-relay:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("iroh-relay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", ":3340", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return http.ListenAndServe(*addr, relayserver.New())
}
