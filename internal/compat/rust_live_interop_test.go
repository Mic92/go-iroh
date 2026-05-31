package compat

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
)

const liveRustInteropEnv = "GO_IROH_LIVE_RUST_INTEROP"
const rustIrohBinEnv = "GO_IROH_RUST_IROH_BIN"
const rustListenBinEnv = "GO_IROH_RUST_LISTEN_BIN"
const rustRepoEnv = "IROH_RUST_REPO"

func TestLiveRustInteropGoSidePreconditions(t *testing.T) {
	maxPathID := uint32(4)
	qntLimit := uint8(32)
	cfg := &quic.Config{
		EnableDatagrams:                true,
		InitialMaxPathID:               &maxPathID,
		MaxRemoteNATTraversalAddresses: &qntLimit,
		SendObservedAddressReports:     true,
		ReceiveObservedAddressReports:  true,
	}

	if !cfg.EnableDatagrams {
		t.Fatal("datagrams disabled")
	}
	if cfg.InitialMaxPathID == nil || *cfg.InitialMaxPathID < 1 {
		t.Fatalf("InitialMaxPathID = %v, want non-zero", cfg.InitialMaxPathID)
	}
	if cfg.MaxRemoteNATTraversalAddresses == nil || *cfg.MaxRemoteNATTraversalAddresses == 0 {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %v, want non-zero", cfg.MaxRemoteNATTraversalAddresses)
	}
	if !cfg.SendObservedAddressReports || !cfg.ReceiveObservedAddressReports {
		t.Fatalf("QAD reports send=%v receive=%v, want both true", cfg.SendObservedAddressReports, cfg.ReceiveObservedAddressReports)
	}
}

func TestRustIrohBin(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		t.Setenv(rustIrohBinEnv, "/tmp/rust-iroh")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustIrohBin()
		if !ok {
			t.Fatal("rustIrohBin ok = false, want true")
		}
		if bin != "/tmp/rust-iroh" {
			t.Fatalf("rustIrohBin bin = %q, want /tmp/rust-iroh", bin)
		}
		if len(checked) != 0 {
			t.Fatalf("rustIrohBin checked = %v, want none", checked)
		}
	})

	t.Run("repo", func(t *testing.T) {
		t.Setenv(rustIrohBinEnv, "")
		repo := t.TempDir()
		bin := filepath.Join(repo, "target", "debug", "iroh")
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(rustRepoEnv, repo)
		got, checked, ok := rustIrohBin()
		if !ok {
			t.Fatal("rustIrohBin ok = false, want true")
		}
		if got != bin {
			t.Fatalf("rustIrohBin bin = %q, want %q", got, bin)
		}
		if len(checked) != 1 || checked[0] != bin {
			t.Fatalf("rustIrohBin checked = %v, want [%q]", checked, bin)
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv(rustIrohBinEnv, "")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustIrohBin()
		if ok {
			t.Fatal("rustIrohBin ok = true, want false")
		}
		if bin != "" || len(checked) != 0 {
			t.Fatalf("rustIrohBin = %q, %v, want empty", bin, checked)
		}
	})
}

func TestRustListenExampleBin(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		t.Setenv(rustListenBinEnv, "/tmp/rust-listen")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustListenExampleBin()
		if !ok {
			t.Fatal("rustListenExampleBin ok = false, want true")
		}
		if bin != "/tmp/rust-listen" {
			t.Fatalf("rustListenExampleBin bin = %q, want /tmp/rust-listen", bin)
		}
		if len(checked) != 0 {
			t.Fatalf("rustListenExampleBin checked = %v, want none", checked)
		}
	})

	t.Run("repo", func(t *testing.T) {
		t.Setenv(rustListenBinEnv, "")
		repo := t.TempDir()
		bin := filepath.Join(repo, "target", "debug", "examples", "listen")
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(rustRepoEnv, repo)
		got, checked, ok := rustListenExampleBin()
		if !ok {
			t.Fatal("rustListenExampleBin ok = false, want true")
		}
		if got != bin {
			t.Fatalf("rustListenExampleBin bin = %q, want %q", got, bin)
		}
		if len(checked) != 1 || checked[0] != bin {
			t.Fatalf("rustListenExampleBin checked = %v, want [%q]", checked, bin)
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv(rustListenBinEnv, "")
		t.Setenv(rustRepoEnv, "")
		bin, checked, ok := rustListenExampleBin()
		if ok {
			t.Fatal("rustListenExampleBin ok = true, want false")
		}
		if bin != "" || len(checked) != 0 {
			t.Fatalf("rustListenExampleBin = %q, %v, want empty", bin, checked)
		}
	})
}

func TestRustIrohHelp(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "iroh")
	script := `#!/bin/sh
if [ "$1" = "--help" ]; then
	echo "Usage: iroh [COMMAND]"
	exit 0
fi
exit 2
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := rustIrohHelp(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if firstLine(out) != "Usage: iroh [COMMAND]" {
		t.Fatalf("first help line = %q, want Usage: iroh [COMMAND]", firstLine(out))
	}
}

func TestLiveRustInteropGate(t *testing.T) {
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with %s or %s pointing at a local Rust iroh checkout; this test never downloads or builds Rust dependencies", liveRustInteropEnv, rustIrohBinEnv, rustRepoEnv)
	}

	bin, checked, ok := rustIrohBin()
	if !ok {
		t.Skipf("%s not set and no local Rust iroh artifact found via %s; checked %v", rustIrohBinEnv, rustRepoEnv, checked)
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("%s=%q, want absolute path", rustIrohBinEnv, bin)
	}
	if st, err := os.Stat(bin); err != nil {
		t.Skipf("Rust iroh binary %s not found: %v", bin, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("Rust iroh binary %s is not executable", bin)
	}

	out, err := rustIrohHelp(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Rust iroh --help succeeded: %s", firstLine(out))
}

func TestLiveRustListenExampleStarts(t *testing.T) {
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with %s or %s pointing at a built Rust listen example; this test never downloads or builds Rust dependencies", liveRustInteropEnv, rustListenBinEnv, rustRepoEnv)
	}

	bin, checked, ok := rustListenExampleBin()
	if !ok {
		t.Skipf("%s not set and no local Rust listen example found via %s; checked %v", rustListenBinEnv, rustRepoEnv, checked)
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("%s=%q, want absolute path", rustListenBinEnv, bin)
	}
	if st, err := os.Stat(bin); err != nil {
		t.Skipf("Rust listen example %s not found: %v", bin, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("Rust listen example %s is not executable", bin)
	}

	out, err := startRustPeerProbe(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if line := firstLine(out); line != "" {
		t.Logf("Rust listen example started: %s", line)
	} else {
		t.Log("Rust listen example started")
	}
}

func rustIrohBin() (bin string, checked []string, ok bool) {
	return rustBinFromEnvOrRepo(rustIrohBinEnv, filepath.Join("target", "debug", "iroh"), filepath.Join("target", "release", "iroh"))
}

func rustListenExampleBin() (bin string, checked []string, ok bool) {
	return rustBinFromEnvOrRepo(rustListenBinEnv,
		filepath.Join("target", "debug", "examples", "listen"),
		filepath.Join("target", "release", "examples", "listen"),
	)
}

func rustBinFromEnvOrRepo(env string, names ...string) (bin string, checked []string, ok bool) {
	if bin := os.Getenv(env); bin != "" {
		return bin, nil, true
	}
	repo := os.Getenv(rustRepoEnv)
	if repo == "" {
		return "", nil, false
	}
	for _, name := range names {
		path := filepath.Join(repo, name)
		checked = append(checked, path)
		if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return path, checked, true
		}
	}
	return "", checked, false
}

func rustIrohHelp(t *testing.T, bin string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"home", "config", "cache", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			return "", err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "--help")
	cmd.Env = append(os.Environ(),
		"HOME="+filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s --help: %w", bin, ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("%s --help: %w\n%s", bin, err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("%s --help: empty output", bin)
	}
	return string(out), nil
}

func startRustPeerProbe(t *testing.T, bin string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"home", "config", "cache", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			return "", err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"HOME="+filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
	)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%s: %w", bin, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err == nil {
			return out.String(), fmt.Errorf("%s exited during startup\n%s", bin, out.String())
		}
		return out.String(), fmt.Errorf("%s exited during startup: %w\n%s", bin, err, out.String())
	case <-time.After(2 * time.Second):
	}

	cancel()
	select {
	case err := <-done:
		if ctx.Err() == nil && err != nil {
			return out.String(), fmt.Errorf("%s wait: %w\n%s", bin, err, out.String())
		}
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return out.String(), fmt.Errorf("%s did not stop after cancellation\n%s", bin, out.String())
	}
	return out.String(), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
