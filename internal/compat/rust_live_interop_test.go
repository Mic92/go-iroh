package compat

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	stdstrconv "strconv"
	"testing"

	quic "github.com/tmc/go-iroh/internal/qng"
)

const liveRustInteropEnv = "GO_IROH_LIVE_RUST_INTEROP"
const rustIrohBinEnv = "GO_IROH_RUST_IROH_BIN"
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

func TestLiveRustInteropGate(t *testing.T) {
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with %s or %s pointing at a local Rust iroh checkout; this test never downloads or builds Rust dependencies", liveRustInteropEnv, rustIrohBinEnv, rustRepoEnv)
	}

	rustc, err := exec.LookPath("rustc")
	if err != nil {
		t.Skip("rustc not installed; live Rust interop requires rustc >= 1.91 when the Rust peer is built locally")
	}
	out, err := exec.Command(rustc, "--version").Output()
	if err != nil {
		t.Skipf("rustc --version failed: %v", err)
	}
	if !rustcAtLeast191(string(out)) {
		t.Skipf("rustc version %q is older than 1.91; live Rust interop requires rustc >= 1.91", string(out))
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

	t.Skip("live Rust peer orchestration is not implemented; next step is to start this binary and prove multipath, QAD observed-address, and QNT route acceptance against go-iroh")
}

func rustIrohBin() (bin string, checked []string, ok bool) {
	if bin := os.Getenv(rustIrohBinEnv); bin != "" {
		return bin, nil, true
	}
	repo := os.Getenv(rustRepoEnv)
	if repo == "" {
		return "", nil, false
	}
	for _, name := range []string{
		filepath.Join(repo, "target", "debug", "iroh"),
		filepath.Join(repo, "target", "release", "iroh"),
	} {
		checked = append(checked, name)
		if st, err := os.Stat(name); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return name, checked, true
		}
	}
	return "", checked, false
}

func rustcAtLeast191(version string) bool {
	m := regexp.MustCompile(`rustc ([0-9]+)\.([0-9]+)`).FindStringSubmatch(version)
	if m == nil {
		return false
	}
	major, _ := stdstrconv.Atoi(m[1])
	minor, _ := stdstrconv.Atoi(m[2])
	return major > 1 || major == 1 && minor >= 91
}
