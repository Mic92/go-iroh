// Package compat holds cross-implementation parity tests that compare go-iroh
// output against the reference Rust iroh implementation.
//
// The comparison is gated: it runs only when cargo is installed and the
// IROH_RUST_REPO environment variable points at a local checkout of
// github.com/n0-computer/iroh. Otherwise the test skips, since the Rust
// toolchain and source are an external dependency, not always present.
package compat

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rustEnv resolves the gate: returns the iroh-base path or skips the test.
func rustEnv(t *testing.T) (irohBase string) {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not installed; skipping Rust parity comparison")
	}
	repo := os.Getenv("IROH_RUST_REPO")
	if repo == "" {
		// Best-effort default: the sibling checkout this port was built from.
		repo = "/Volumes/tmc/go/src/github.com/n0-computer/iroh"
	}
	base := filepath.Join(repo, "iroh-base")
	if _, err := os.Stat(filepath.Join(base, "Cargo.toml")); err != nil {
		t.Skipf("iroh-base not found at %s (set IROH_RUST_REPO); skipping", base)
	}
	return base
}

// buildRustRef generates a Cargo project for the rustref binary pointing at the
// given iroh-base path, builds it, and returns the binary path.
func buildRustRef(t *testing.T, irohBase string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml(irohBase)), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("rustref/main.rs")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	// iroh-base requires a recent rustc. Allow an override via IROH_RUST_TOOLCHAIN
	// (e.g. "1.94.1") passed to cargo as a +toolchain selector.
	args := []string{}
	if tc := os.Getenv("IROH_RUST_TOOLCHAIN"); tc != "" {
		args = append(args, "+"+tc)
	}
	args = append(args, "build", "--release", "--quiet")
	cmd := exec.Command("cargo", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cargo build failed (rustc too old or deps unavailable; set IROH_RUST_TOOLCHAIN): %v\n%s", err, out)
	}
	return filepath.Join(dir, "target", "release", "rustref")
}

func cargoToml(irohBase string) string {
	return `[package]
name = "rustref"
version = "0.0.0"
edition = "2021"
publish = false

[[bin]]
name = "rustref"
path = "main.rs"

[dependencies]
iroh-base = { path = ` + strconv(irohBase) + `, default-features = false, features = ["key", "relay"] }
data-encoding = "2"
`
}

func strconv(s string) string { return "\"" + s + "\"" }

// goIroh builds the go-iroh CLI once and returns its path.
func goIroh(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "iroh")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/tmc/go-iroh/cmd/iroh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build iroh: %v\n%s", err, out)
	}
	return bin
}

func runOut(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return strings.TrimSpace(string(out))
}

// TestKeyParity compares go-iroh and Rust iroh-base for key derivation, z-base-32
// encoding, and ed25519 signing across several seeds.
func TestKeyParity(t *testing.T) {
	irohBase := rustEnv(t)
	rust := buildRustRef(t, irohBase)
	go_ := goIroh(t)

	seeds := []string{
		strings.Repeat("00", 32),
		strings.Repeat("2a", 32),
		strings.Repeat("ff", 32),
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, seed := range seeds {
		t.Run("seed_"+seed[:8], func(t *testing.T) {
			// public key
			gp := runOut(t, go_, "key", "public", seed)
			rp := runOut(t, rust, "key", "public", seed)
			if gp != rp {
				t.Errorf("public mismatch: go=%s rust=%s", gp, rp)
			}
			// z32 of the public key
			gz := runOut(t, go_, "key", "z32", gp)
			rz := runOut(t, rust, "key", "z32", rp)
			if gz != rz {
				t.Errorf("z32 mismatch: go=%s rust=%s", gz, rz)
			}
			// signature over a fixed message
			gs := runOut(t, go_, "sign", seed, "parity check")
			rs := runOut(t, rust, "sign", seed, "parity check")
			if gs != rs {
				t.Errorf("signature mismatch: go=%s rust=%s", gs, rs)
			}
		})
	}
}
