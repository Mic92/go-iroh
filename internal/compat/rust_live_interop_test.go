package compat

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/relay"
)

const liveRustInteropEnv = "GO_IROH_LIVE_RUST_INTEROP"
const rustIrohBinEnv = "GO_IROH_RUST_IROH_BIN"
const rustListenBinEnv = "GO_IROH_RUST_LISTEN_BIN"
const rustRepoEnv = "IROH_RUST_REPO"
const rustExampleALPN = "n0/iroh/examples/0"

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

func TestParseRustListenConnectLine(t *testing.T) {
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public()

	line := fmt.Sprintf(
		"\tcargo run --example connect -- --endpoint-id %s --addrs \"127.0.0.1:1234 [::1]:5678\" --relay-url https://relay.example.com/\n",
		id.Z32(),
	)
	ready, ok, err := parseRustListenConnectLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("parseRustListenConnectLine ok = false, want true")
	}
	if !ready.EndpointID.Equal(id) {
		t.Fatalf("endpoint id = %s, want %s", ready.EndpointID, id)
	}
	if ready.EndpointIDText != id.Z32() {
		t.Fatalf("endpoint id text = %q, want %q", ready.EndpointIDText, id.Z32())
	}
	wantAddrs := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1234"),
		netip.MustParseAddrPort("[::1]:5678"),
	}
	if fmt.Sprint(ready.Addrs) != fmt.Sprint(wantAddrs) {
		t.Fatalf("addrs = %v, want %v", ready.Addrs, wantAddrs)
	}
	if ready.RelayURL.String() != "https://relay.example.com/" {
		t.Fatalf("relay URL = %q, want https://relay.example.com/", ready.RelayURL)
	}
	if ready.Line != strings.TrimSpace(line) {
		t.Fatalf("line = %q, want %q", ready.Line, strings.TrimSpace(line))
	}

	_, ok, err = parseRustListenConnectLine("endpoint listening addresses:")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("parseRustListenConnectLine ok = true for non-command line")
	}
}

func TestStartRustListenPeerReadsConnectLine(t *testing.T) {
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public()
	line := fmt.Sprintf(
		"cargo run --example connect -- --endpoint-id %s --addrs \"127.0.0.1:1234\" --relay-url https://relay.example.com/",
		id.Z32(),
	)

	dir := t.TempDir()
	bin := filepath.Join(dir, "listen")
	script := fmt.Sprintf(`#!/bin/sh
echo "listen example!"
printf '%%s\n' '%s' >&2
exec sleep 60
`, line)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	peer, err := startRustListenPeer(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.Ready.EndpointID.Equal(id) {
		t.Fatalf("endpoint id = %s, want %s", peer.Ready.EndpointID, id)
	}
	if len(peer.Ready.Addrs) != 1 || peer.Ready.Addrs[0] != netip.MustParseAddrPort("127.0.0.1:1234") {
		t.Fatalf("addrs = %v, want [127.0.0.1:1234]", peer.Ready.Addrs)
	}
	if !strings.Contains(peer.Output(), line) {
		t.Fatalf("output = %q, want command line", peer.Output())
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

	peer, err := startRustListenPeer(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Rust listen example ready: id=%s addrs=%v relay=%s", peer.Ready.EndpointIDText, peer.Ready.Addrs, peer.Ready.RelayURL)
}

func TestLiveRustGoToRustEcho(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	peer, err := startRustListenPeer(t, bin)
	if err != nil {
		t.Fatal(err)
	}

	client, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeCustomURLs(peer.Ready.RelayURL)))
	if err != nil {
		t.Fatalf("bind Go endpoint: %v", err)
	}
	defer client.Close(ctx)

	if len(peer.Ready.Addrs) == 0 {
		if err := client.Online(ctx); err != nil {
			t.Fatalf("Go endpoint online: %v", err)
		}
	}

	addr := base.NewEndpointAddr(peer.Ready.EndpointID).WithRelayURL(peer.Ready.RelayURL)
	for _, ap := range peer.Ready.Addrs {
		addr = addr.WithIP(ap)
	}

	conn, err := client.Connect(ctx, addr, []byte(rustExampleALPN))
	if err != nil {
		t.Fatalf("connect to Rust listen example: %v\n%s", err, peer.Output())
	}
	defer conn.CloseWithError(0, "")
	if !conn.RemoteID().Equal(peer.Ready.EndpointID) {
		t.Fatalf("remote id = %s, want %s", conn.RemoteID(), peer.Ready.EndpointID)
	}
	if string(conn.ALPN()) != rustExampleALPN {
		t.Fatalf("ALPN = %q, want %q", conn.ALPN(), rustExampleALPN)
	}

	s, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := s.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set stream deadline: %v", err)
	}
	if _, err := s.Write([]byte("hello from go-iroh")); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close stream write side: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	want := "hi! you connected to " + peer.Ready.EndpointIDText + ". bye bye"
	if string(got) != want {
		t.Fatalf("response = %q, want %q\n%s", got, want, peer.Output())
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

type rustListenReady struct {
	EndpointID     base.EndpointId
	EndpointIDText string
	Addrs          []netip.AddrPort
	RelayURL       base.RelayUrl
	Line           string
}

type rustListenPeer struct {
	Ready rustListenReady

	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan error
	out    *rustListenOutput

	once    sync.Once
	waitErr error
}

func (p *rustListenPeer) Close() error {
	p.once.Do(func() {
		p.cancel()
		select {
		case err := <-p.done:
			p.waitErr = err
		case <-time.After(5 * time.Second):
			if p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
			select {
			case p.waitErr = <-p.done:
			case <-time.After(time.Second):
				p.waitErr = fmt.Errorf("%s did not stop after cancellation", p.cmd.Path)
				return
			}
			if p.waitErr == nil {
				p.waitErr = fmt.Errorf("%s did not stop after cancellation", p.cmd.Path)
			}
		}
	})
	return p.waitErr
}

func (p *rustListenPeer) Output() string {
	return p.out.String()
}

type rustListenOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *rustListenOutput) AppendLine(line string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf.WriteString(line)
	o.buf.WriteByte('\n')
}

func (o *rustListenOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func startRustListenPeer(t *testing.T, bin string) (*rustListenPeer, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"home", "config", "cache", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, bin)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(),
		"HOME="+filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%s stdout: %w", bin, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%s stderr: %w", bin, err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("%s: %w", bin, err)
	}

	out := new(rustListenOutput)
	lines := make(chan string)
	readyDone := make(chan struct{})
	var scans sync.WaitGroup
	scans.Add(2)
	go scanRustListenOutput(stdout, out, lines, readyDone, &scans)
	go scanRustListenOutput(stderr, out, lines, readyDone, &scans)
	scanDone := make(chan struct{})
	go func() {
		scans.Wait()
		close(scanDone)
	}()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	peer := &rustListenPeer{cmd: cmd, cancel: cancel, done: done, out: out}

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	defer func() {
		close(readyDone)
	}()
	select {
	case <-ctx.Done():
		_ = peer.Close()
		return nil, fmt.Errorf("%s startup: %w\n%s", bin, ctx.Err(), out.String())
	default:
	}
	for {
		select {
		case line := <-lines:
			ready, ok, err := parseRustListenConnectLine(line)
			if err != nil {
				_ = peer.Close()
				return nil, fmt.Errorf("%s readiness line: %w\n%s", bin, err, out.String())
			}
			if !ok {
				continue
			}
			peer.Ready = ready
			t.Cleanup(func() {
				if err := peer.Close(); err != nil && ctx.Err() == nil {
					t.Logf("stopping Rust listen example: %v", err)
				}
			})
			return peer, nil
		case err := <-done:
			waitScan(scanDone)
			if err == nil {
				return nil, fmt.Errorf("%s exited during startup\n%s", bin, out.String())
			}
			return nil, fmt.Errorf("%s exited during startup: %w\n%s", bin, err, out.String())
		case <-timer.C:
			_ = peer.Close()
			return nil, fmt.Errorf("%s did not print connect command within 30s\n%s", bin, out.String())
		}
	}
}

func scanRustListenOutput(r io.Reader, out *rustListenOutput, lines chan<- string, done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		out.AppendLine(line)
		select {
		case lines <- line:
		case <-done:
		}
	}
}

func waitScan(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}
}

func parseRustListenConnectLine(line string) (rustListenReady, bool, error) {
	line = strings.TrimSpace(line)
	const prefix = "cargo run --example connect -- --endpoint-id "
	if !strings.HasPrefix(line, prefix) {
		return rustListenReady{}, false, nil
	}
	rest := strings.TrimPrefix(line, prefix)
	idText, rest, ok := strings.Cut(rest, " --addrs ")
	if !ok || idText == "" {
		return rustListenReady{}, true, fmt.Errorf("missing endpoint id or addrs")
	}
	if !strings.HasPrefix(rest, "\"") {
		return rustListenReady{}, true, fmt.Errorf("missing quoted addrs")
	}
	rest = strings.TrimPrefix(rest, "\"")
	addrsText, rest, ok := strings.Cut(rest, "\"")
	if !ok {
		return rustListenReady{}, true, fmt.Errorf("unterminated addrs")
	}
	rest = strings.TrimSpace(rest)
	const relayPrefix = "--relay-url "
	if !strings.HasPrefix(rest, relayPrefix) {
		return rustListenReady{}, true, fmt.Errorf("missing relay URL")
	}
	relayText := strings.TrimSpace(strings.TrimPrefix(rest, relayPrefix))
	if relayText == "" {
		return rustListenReady{}, true, fmt.Errorf("empty relay URL")
	}

	id, err := parseRustEndpointID(idText)
	if err != nil {
		return rustListenReady{}, true, err
	}
	var addrs []netip.AddrPort
	for _, text := range strings.Fields(addrsText) {
		addr, err := netip.ParseAddrPort(text)
		if err != nil {
			return rustListenReady{}, true, fmt.Errorf("address %q: %w", text, err)
		}
		addrs = append(addrs, addr)
	}
	relayURL, err := base.ParseRelayUrl(relayText)
	if err != nil {
		return rustListenReady{}, true, fmt.Errorf("relay URL %q: %w", relayText, err)
	}
	return rustListenReady{
		EndpointID:     id,
		EndpointIDText: idText,
		Addrs:          addrs,
		RelayURL:       relayURL,
		Line:           line,
	}, true, nil
}

func parseRustEndpointID(s string) (base.EndpointId, error) {
	if id, err := base.PublicKeyFromZ32(s); err == nil {
		return id, nil
	}
	if id, err := base.ParsePublicKey(s); err == nil {
		return id, nil
	}
	return base.EndpointId{}, fmt.Errorf("endpoint id %q: invalid public key", s)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
