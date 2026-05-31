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

func TestLiveRustInteropGate(t *testing.T) {
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with GO_IROH_RUST_IROH_BIN pointing at a local Rust iroh binary; this test never downloads or builds Rust dependencies", liveRustInteropEnv)
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

	bin := os.Getenv("GO_IROH_RUST_IROH_BIN")
	if bin == "" {
		t.Skip("GO_IROH_RUST_IROH_BIN not set; live Rust interop needs an existing Rust iroh binary")
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("GO_IROH_RUST_IROH_BIN=%q, want absolute path", bin)
	}
	if st, err := os.Stat(bin); err != nil {
		t.Skipf("Rust iroh binary %s not found: %v", bin, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("Rust iroh binary %s is not executable", bin)
	}

	t.Skip("live Rust peer orchestration is not implemented; next step is to start this binary and prove multipath, QAD observed-address, and QNT route acceptance against go-iroh")
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
