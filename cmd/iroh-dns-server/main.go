// Command iroh-dns-server runs the pkarr HTTP surface used by iroh DNS.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/tmc/go-iroh/internal/pkarrserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "iroh-dns-server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("iroh-dns-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", ":3350", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return http.ListenAndServe(*addr, pkarrserver.New())
}
