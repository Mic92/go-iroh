//go:build interop

package iroh_test

import (
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
)

const rustExampleALPN = "n0/iroh/examples/0"

func TestRustConnectExampleEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	repo := rustIrohRepo(t)
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skipf("cargo not found: %v", err)
	}
	build := exec.CommandContext(ctx, "cargo", "build", "-p", "iroh", "--example", "connect")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("build Rust iroh connect example: %v\n%s", err, out)
	}

	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(rustExampleALPN),
		iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatalf("bind Go endpoint: %v", err)
	}
	defer server.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		msg, err := io.ReadAll(stream)
		if err != nil {
			done <- err
			return
		}
		if !strings.Contains(string(msg), "is saying 'hello!'") {
			done <- errUnexpectedRustMessage(string(msg))
			return
		}
		if _, err := stream.Write([]byte("hi! you connected to " + server.ID().String() + ". bye bye")); err != nil {
			done <- err
			return
		}
		if err := stream.Close(); err != nil {
			done <- err
			return
		}
		select {
		case <-conn.Context().Done():
			done <- nil
		case <-ctx.Done():
			done <- ctx.Err()
		}
	}()

	bin := filepath.Join(repo, "target", "debug", "examples", "connect")
	cmd := exec.CommandContext(ctx, bin,
		"--endpoint-id", server.ID().String(),
		"--addrs", server.LocalAddr().String(),
		"--relay-url", "https://usw1-1.relay.n0.iroh-canary.iroh.link./",
	)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run Rust iroh connect example: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "received: hi! you connected to "+server.ID().String()+". bye bye") {
		t.Fatalf("Rust connect output = %s", out)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func rustIrohRepo(t *testing.T) string {
	t.Helper()
	if repo := os.Getenv("IROH_RUST_REPO"); repo != "" {
		return repo
	}
	const repo = "/Users/tmc/go/src/github.com/n0-computer/iroh"
	if _, err := os.Stat(filepath.Join(repo, "Cargo.toml")); err != nil {
		t.Skipf("Rust iroh checkout not found at %s: %v", repo, err)
	}
	return repo
}

type errUnexpectedRustMessage string

func (e errUnexpectedRustMessage) Error() string {
	return "unexpected Rust message: " + string(e)
}
