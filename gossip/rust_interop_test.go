package gossip_test

import (
	"bufio"
	"context"
	"encoding/json"
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

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const liveRustGossipEnv = "GO_IROH_LIVE_RUST_GOSSIP"
const rustGossipBinEnv = "GO_IROH_RUST_GOSSIP_BIN"

func TestLiveRustGossipInterop(t *testing.T) {
	bin := requireLiveRustGossipHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	run := startRustGossipHelper(t, ctx, bin)
	ready := run.Ready(ctx, t)
	rustID, err := key.ParseEndpointID(ready.ID)
	if err != nil {
		t.Fatalf("parse Rust endpoint id %q: %v\n%s", ready.ID, err, run.Output())
	}
	if len(ready.Addrs) == 0 {
		t.Fatalf("Rust helper reported no direct addresses\n%s", run.Output())
	}
	rustAP, err := netip.ParseAddrPort(ready.Addrs[0])
	if err != nil {
		t.Fatalf("parse Rust direct addr %q: %v\n%s", ready.Addrs[0], err, run.Output())
	}

	var topic gossip.TopicID
	copy(topic[:], []byte("go-iroh rust gossip interop 001!"))

	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatalf("bind Go endpoint: %v", err)
	}
	goGossip := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: goGossip.Handler(),
	}, nil)
	if err != nil {
		t.Fatalf("new Go router: %v", err)
	}
	defer router.Shutdown(ctx)

	rustAddr := netaddr.NewEndpointAddr(rustID).WithIP(rustAP)
	goTopic, err := goGossip.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{rustAddr})
	if err != nil {
		t.Fatalf("Go subscribe and join Rust: %v\n%s", err, run.Output())
	}
	defer goTopic.Close()

	if ev := nextEvent(ctx, t, goTopic); ev.Kind != gossip.NeighborUp || !ev.Peer.Equal(rustID) {
		t.Fatalf("Go first event = %+v, want NeighborUp(%s)\n%s", ev, rustID, run.Output())
	}
	run.Expect(ctx, t, "NeighborUp", "")

	const goToRust = "hello from go"
	if err := goTopic.Broadcast(ctx, []byte(goToRust)); err != nil {
		t.Fatalf("Go broadcast to Rust: %v\n%s", err, run.Output())
	}
	run.Expect(ctx, t, "Received", goToRust)

	const rustToGo = "hello from rust"
	run.Broadcast(ctx, t, rustToGo)
	for {
		ev := nextEvent(ctx, t, goTopic)
		if ev.Kind != gossip.Received {
			continue
		}
		if string(ev.Content) != rustToGo {
			t.Fatalf("Go received %q, want %q\n%s", ev.Content, rustToGo, run.Output())
		}
		if !ev.DeliveredFrom.Equal(rustID) {
			t.Fatalf("Go delivery peer = %s, want %s\n%s", ev.DeliveredFrom, rustID, run.Output())
		}
		break
	}
}

type rustGossipReady struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs"`
}

type rustGossipEvent struct {
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Addrs   []string `json:"addrs"`
	Peer    string   `json:"peer"`
	Content string   `json:"content"`
	Raw     string
}

type rustGossipRun struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	ready  chan rustGossipReady
	events chan rustGossipEvent
	done   chan error

	mu  sync.Mutex
	out strings.Builder
}

func requireLiveRustGossipHelper(t *testing.T) string {
	t.Helper()
	if os.Getenv(liveRustGossipEnv) != "1" {
		t.Skipf("set %s=1 to build and run the Rust iroh-gossip interop helper", liveRustGossipEnv)
	}
	if bin := os.Getenv(rustGossipBinEnv); bin != "" {
		if !filepath.IsAbs(bin) {
			t.Fatalf("%s=%q, want absolute path", rustGossipBinEnv, bin)
		}
		return bin
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skipf("cargo not found: %v", err)
	}
	src := filepath.Join("testdata", "rust-gossip-interop")
	tmp := filepath.Join(t.TempDir(), "rust-gossip-interop")
	if err := copyRustGossipHelper(tmp, src); err != nil {
		t.Fatalf("copy Rust helper: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	cmd := exec.Command("cargo", "build", "--quiet", "--manifest-path", filepath.Join(tmp, "Cargo.toml"), "--target-dir", target)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build Rust gossip helper: %v\n%s", err, out)
	}
	return filepath.Join(target, "debug", "go-iroh-rust-gossip-interop")
}

func copyRustGossipHelper(dst, src string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, 0o644)
	})
}

func startRustGossipHelper(t *testing.T, ctx context.Context, bin string) *rustGossipRun {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Rust helper stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Rust helper stdout: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Rust helper stderr: %v", err)
	}
	run := &rustGossipRun{
		cmd:    cmd,
		stdin:  stdin,
		ready:  make(chan rustGossipReady, 1),
		events: make(chan rustGossipEvent, 16),
		done:   make(chan error, 1),
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Rust helper: %v", err)
	}
	go run.scan(stdout)
	go run.scan(stderr)
	go func() { run.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
		}
	})
	return run
}

func (r *rustGossipRun) Ready(ctx context.Context, t *testing.T) rustGossipReady {
	t.Helper()
	select {
	case ready := <-r.ready:
		return ready
	case err := <-r.done:
		t.Fatalf("Rust helper exited before ready: %v\n%s", err, r.Output())
	case <-ctx.Done():
		t.Fatalf("Rust helper ready: %v\n%s", ctx.Err(), r.Output())
	}
	return rustGossipReady{}
}

func (r *rustGossipRun) Expect(ctx context.Context, t *testing.T, kind, content string) {
	t.Helper()
	for {
		select {
		case ev := <-r.events:
			if ev.Kind != kind {
				continue
			}
			if content != "" && ev.Content != content {
				continue
			}
			return
		case err := <-r.done:
			t.Fatalf("Rust helper exited waiting for %s: %v\n%s", kind, err, r.Output())
		case <-ctx.Done():
			t.Fatalf("Rust helper event %s: %v\n%s", kind, ctx.Err(), r.Output())
		}
	}
}

func (r *rustGossipRun) Broadcast(ctx context.Context, t *testing.T, content string) {
	t.Helper()
	cmd := struct {
		Cmd     string `json:"cmd"`
		Content string `json:"content"`
	}{Cmd: "Broadcast", Content: content}
	b, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal Rust broadcast command: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := fmt.Fprintf(r.stdin, "%s\n", b)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write Rust broadcast command: %v\n%s", err, r.Output())
		}
	case <-ctx.Done():
		t.Fatalf("write Rust broadcast command: %v\n%s", ctx.Err(), r.Output())
	}
}

func (r *rustGossipRun) scan(out io.Reader) {
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		r.append(line)
		var ev rustGossipEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		ev.Raw = line
		if ev.Kind == "Ready" {
			r.ready <- rustGossipReady{ID: ev.ID, Addrs: ev.Addrs}
			continue
		}
		r.events <- ev
	}
}

func (r *rustGossipRun) append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.out.WriteString(line)
	r.out.WriteByte('\n')
}

func (r *rustGossipRun) Output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}
