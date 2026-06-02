// Command iroh is a small utility for working with iroh identities and
// addresses: generating and inspecting keys, and parsing endpoint info.
//
// It exercises the go-iroh key, netaddr, and dns packages and is the subject of
// the scripttest-based CLI tests (including comparison against the Rust iroh
// tools).
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "iroh:", err)
		os.Exit(1)
	}
}

const usage = `usage: iroh <command> [args]

commands:
  key gen [--seed=<hex32>]   generate a secret key (prints secret hex)
  key public <secret-hex>    print the public key (endpoint id) for a secret
  key z32 <key>              print the z-base-32 form of a public key
  id parse <key>             parse and re-print a public key (hex)
  addr parse <addr>          parse a transport address and re-print it
  sign <secret-hex> <msg>    sign msg, print signature hex
  verify <pub> <sig-hex> <msg>  verify a signature (exit 0 ok, 1 fail)
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("no command")
	}
	switch args[0] {
	case "key":
		return cmdKey(args[1:], stdin, stdout)
	case "id":
		return cmdID(args[1:], stdout)
	case "addr":
		return cmdAddr(args[1:], stdout)
	case "sign":
		return cmdSign(args[1:], stdout)
	case "verify":
		return cmdVerify(args[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdKey(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("key: missing subcommand")
	}
	switch args[0] {
	case "gen":
		var seed [key.SecretKeyLength]byte
		seedSet := false
		for _, a := range args[1:] {
			if s, ok := strings.CutPrefix(a, "--seed="); ok {
				b, err := hex.DecodeString(s)
				if err != nil || len(b) != key.SecretKeyLength {
					return fmt.Errorf("key gen: --seed must be %d hex bytes", key.SecretKeyLength)
				}
				copy(seed[:], b)
				seedSet = true
			}
		}
		if !seedSet {
			if _, err := rand.Read(seed[:]); err != nil {
				return err
			}
		}
		sk := key.NewSecretKey(seed)
		b := sk.Bytes()
		fmt.Fprintln(stdout, hex.EncodeToString(b[:]))
		return nil
	case "public":
		if len(args) < 2 {
			return fmt.Errorf("key public: missing secret hex")
		}
		sk, err := key.ParseSecretKey(args[1])
		if err != nil {
			return fmt.Errorf("key public: %w", err)
		}
		fmt.Fprintln(stdout, sk.Public().String())
		return nil
	case "z32":
		if len(args) < 2 {
			return fmt.Errorf("key z32: missing key")
		}
		pk, err := key.ParsePublicKey(args[1])
		if err != nil {
			return fmt.Errorf("key z32: %w", err)
		}
		fmt.Fprintln(stdout, pk.Z32())
		return nil
	default:
		return fmt.Errorf("key: unknown subcommand %q", args[0])
	}
}

func cmdID(args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "parse" {
		return fmt.Errorf("id: usage: id parse <key>")
	}
	pk, err := key.ParsePublicKey(args[1])
	if err != nil {
		return fmt.Errorf("id parse: %w", err)
	}
	fmt.Fprintln(stdout, pk.String())
	return nil
}

func cmdAddr(args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "parse" {
		return fmt.Errorf("addr: usage: addr parse <addr>")
	}
	a, err := netaddr.ParseTransportAddr(args[1])
	if err != nil {
		return fmt.Errorf("addr parse: %w", err)
	}
	fmt.Fprintln(stdout, a.String())
	return nil
}

func cmdSign(args []string, stdout io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("sign: usage: sign <secret-hex> <msg>")
	}
	sk, err := key.ParseSecretKey(args[0])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	sig := sk.Sign([]byte(args[1]))
	b := sig.Bytes()
	fmt.Fprintln(stdout, hex.EncodeToString(b[:]))
	return nil
}

func cmdVerify(args []string, stdout io.Writer) error {
	if len(args) < 3 {
		return fmt.Errorf("verify: usage: verify <pub> <sig-hex> <msg>")
	}
	pk, err := key.ParsePublicKey(args[0])
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	sigBytes, err := hex.DecodeString(args[1])
	if err != nil {
		return fmt.Errorf("verify: bad signature hex: %w", err)
	}
	sig, err := key.SignatureFromSlice(sigBytes)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if err := pk.Verify([]byte(args[2]), sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Fprintln(stdout, "ok")
	return nil
}

var _ = bufio.NewReader
