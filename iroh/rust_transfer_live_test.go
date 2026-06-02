package iroh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qlogtest"
	"github.com/tmc/go-iroh/relay"
)

const liveRustInteropEnv = "GO_IROH_LIVE_RUST_INTEROP"
const rustRepoEnv = "IROH_RUST_REPO"
const rustTransferBinEnv = "GO_IROH_RUST_TRANSFER_BIN"
const rustTransferALPN = "n0/iroh/transfer/example/1"

func TestLiveRustTransferFetchPingDirectPath(t *testing.T) {
	bin := requireLiveRustTransferExample(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	goQlogDir := t.TempDir()
	t.Setenv("QLOGDIR", goQlogDir)

	relayURL := relay.StagingMap().URLs()[0]
	server, err := Bind(ctx,
		WithALPNs(rustTransferALPN),
		WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)),
		WithRelayMode(relay.ModeCustomURLs(relayURL)),
	)
	if err != nil {
		t.Fatalf("bind Go endpoint: %v", err)
	}
	defer func() {
		if err := server.Close(context.Background()); err != nil {
			t.Errorf("close Go endpoint: %v", err)
		}
	}()
	if err := server.Online(ctx); err != nil {
		t.Fatalf("Go endpoint online: %v", err)
	}
	if got := server.localNATTraversalCandidates(); len(got) == 0 {
		t.Fatal("Go endpoint has no local QNT candidates")
	}
	t.Logf("Go endpoint ready: id=%s direct=%v relay=%s", server.ID(), server.localNATTraversalCandidates(), relayURL)

	accepted := make(chan liveRustAccept, 1)
	go func() {
		conn, err := server.Accept(ctx)
		accepted <- liveRustAccept{conn: conn, err: err}
	}()

	run, err := startRustTransferFetchPing(t, ctx, bin, server.ID().String(), relayURL.String(), 20)
	if err != nil {
		t.Fatal(err)
	}

	var conn *Conn
	select {
	case got := <-accepted:
		if got.err != nil {
			t.Fatalf("accept Rust transfer fetch: %v\n%s", got.err, run.Output())
		}
		conn = got.conn
	case <-ctx.Done():
		t.Fatalf("accept Rust transfer fetch: %v\n%s", ctx.Err(), run.Output())
	}
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != rustTransferALPN {
		t.Fatalf("ALPN = %q, want %q", conn.ALPN(), rustTransferALPN)
	}
	if !conn.MultipathNegotiated() {
		t.Fatalf("MultipathNegotiated = false, want true\n%s", run.Output())
	}

	if err := run.Wait(ctx); err != nil {
		t.Fatalf("Rust transfer fetch: %v\n%s", err, run.Output())
	}
	ip, ok, err := rustTransferSelectedIP(run.Output())
	if err != nil {
		t.Fatalf("parse Rust transfer output: %v\n%s", err, run.Output())
	}
	if !ok {
		t.Fatalf("Rust transfer output has no selected IP path\n%s", run.Output())
	}
	t.Logf("Rust transfer selected direct path: %s", ip)
	_ = conn.CloseWithError(0, "")

	qlogCtx, qlogCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer qlogCancel()
	goFiles, goFrames, err := waitLiveRustQlogEvidence(qlogCtx, goQlogDir)
	if err != nil {
		t.Fatal(err)
	}
	if goFrames["max_path_id"] == 0 || goFrames["add_address"] == 0 || !hasAnyLiveRustQlogFrame(goFrames, "reach_out", "path_challenge", "path_response", "path_new_connection_id") {
		t.Fatalf("Go qlog frame types = %v, want max_path_id, add_address, and one direct-path proof frame in %v", qlogtest.SortedFrameTypes(goFrames), goFiles)
	}
	t.Logf("Go qlog files: %v", goFiles)
}

type liveRustAccept struct {
	conn *Conn
	err  error
}

type liveRustTransferRun struct {
	cmd     *exec.Cmd
	done    chan error
	out     *liveRustOutput
	scan    sync.WaitGroup
	scanErr chan error
	once    sync.Once
	waitErr error
}

func startRustTransferFetchPing(t *testing.T, ctx context.Context, bin, remoteID, relayURL string, duration int) (*liveRustTransferRun, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"home", "config", "cache", "data", "logs", "qlog"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			return nil, err
		}
	}
	logDir := filepath.Join(dir, "logs")
	qlogDir := filepath.Join(dir, "qlog")

	cmd := exec.CommandContext(ctx, bin,
		"--output", "json",
		"--logs-path", logDir,
		"--qlog",
		"fetch", remoteID,
		"--mode", "ping",
		"--duration", strconv.Itoa(duration),
		"--relay-url", relayURL,
		"--remote-relay-url", relayURL,
		"--no-address-lookup",
		"--bind-addr-v4", "127.0.0.1:0",
	)
	cmd.Env = liveRustEnv(dir, qlogDir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s stdout: %w", bin, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("%s stderr: %w", bin, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", bin, err)
	}

	run := &liveRustTransferRun{
		cmd:     cmd,
		done:    make(chan error, 1),
		out:     new(liveRustOutput),
		scanErr: make(chan error, 2),
	}
	run.scan.Add(2)
	go scanLiveRustOutput(stdout, run.out, run.scanErr, &run.scan)
	go scanLiveRustOutput(stderr, run.out, run.scanErr, &run.scan)
	go func() {
		run.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = run.Wait(ctx)
	})
	return run, nil
}

func liveRustEnv(dir, qlogDir string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "QLOGDIR=") || strings.HasPrefix(kv, "IROH_SECRET=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"HOME="+filepath.Join(dir, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
		"QLOGDIR="+qlogDir,
	)
}

func (r *liveRustTransferRun) Wait(ctx context.Context) error {
	r.once.Do(func() {
		select {
		case err := <-r.done:
			r.waitErr = r.finishWait(err)
		case <-ctx.Done():
			if r.cmd.Process != nil {
				_ = r.cmd.Process.Kill()
			}
			select {
			case err := <-r.done:
				_ = r.finishWait(err)
			case <-time.After(5 * time.Second):
			}
			r.waitErr = ctx.Err()
		}
	})
	return r.waitErr
}

func (r *liveRustTransferRun) finishWait(err error) error {
	r.scan.Wait()
	close(r.scanErr)
	for scanErr := range r.scanErr {
		if scanErr != nil {
			return scanErr
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", r.cmd.Path, err)
	}
	return nil
}

func (r *liveRustTransferRun) Output() string {
	return r.out.String()
}

type liveRustOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *liveRustOutput) AppendLine(line string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf.WriteString(line)
	o.buf.WriteByte('\n')
}

func (o *liveRustOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func scanLiveRustOutput(r io.Reader, out *liveRustOutput, errs chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		out.AppendLine(scanner.Text())
	}
	if err := scanner.Err(); err != nil && !isLiveRustClosedPipe(err) {
		errs <- err
	}
}

func isLiveRustClosedPipe(err error) bool {
	return errors.Is(err, os.ErrClosed) || strings.Contains(err.Error(), "file already closed")
}

func rustTransferSelectedIP(output string) (string, bool, error) {
	var selectedIP string
	var statsHasSelectedIP bool
	var sawPathStats bool
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Kind   string `json:"kind"`
			Status string `json:"status"`
			Addr   struct {
				IP string `json:"Ip"`
			} `json:"addr"`
			Paths []struct {
				RemoteAddr struct {
					IP string `json:"Ip"`
				} `json:"remote_addr"`
			} `json:"paths"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		switch event.Kind {
		case "ConnectionTypeChanged":
			if event.Status == "Selected" && event.Addr.IP != "" {
				selectedIP = event.Addr.IP
			}
		case "PathStats":
			sawPathStats = true
			for _, path := range event.Paths {
				if selectedIP != "" && path.RemoteAddr.IP == selectedIP {
					statsHasSelectedIP = true
				}
			}
		}
	}
	return selectedIP, selectedIP != "" && (!sawPathStats || statsHasSelectedIP), nil
}

func waitLiveRustQlogEvidence(ctx context.Context, dir string) ([]string, map[string]int, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		files, err := qlogtest.Files(dir)
		if err != nil {
			return nil, nil, err
		}
		if len(files) > 0 {
			types, err := qlogtest.FrameTypes(files)
			if err != nil {
				return nil, nil, err
			}
			if types["max_path_id"] > 0 && types["add_address"] > 0 && hasAnyLiveRustQlogFrame(types, "reach_out", "path_challenge", "path_response", "path_new_connection_id") {
				return files, types, nil
			}
		}
		select {
		case <-ctx.Done():
			if len(files) == 0 {
				return nil, nil, fmt.Errorf("found no qlog files in %s: %w", dir, ctx.Err())
			}
			types, _ := qlogtest.FrameTypes(files)
			return nil, nil, fmt.Errorf("qlog frame types = %v, want max_path_id, add_address, and one direct-path proof frame in %v: %w", qlogtest.SortedFrameTypes(types), files, ctx.Err())
		case <-ticker.C:
		}
	}
}

func hasAnyLiveRustQlogFrame(types map[string]int, names ...string) bool {
	for _, name := range names {
		if types[name] > 0 {
			return true
		}
	}
	return false
}

func requireLiveRustTransferExample(t *testing.T) string {
	t.Helper()
	if os.Getenv(liveRustInteropEnv) != "1" {
		t.Skipf("set %s=1 with %s or %s pointing at a built Rust transfer example; this test never downloads or builds Rust dependencies", liveRustInteropEnv, rustTransferBinEnv, rustRepoEnv)
	}

	bin, checked, ok := liveRustBinFromEnvOrRepo(rustTransferBinEnv,
		filepath.Join("target", "debug", "examples", "transfer"),
		filepath.Join("target", "release", "examples", "transfer"),
	)
	if !ok {
		t.Skipf("%s not set and no local Rust transfer example found via %s; checked %v", rustTransferBinEnv, rustRepoEnv, checked)
	}
	if !filepath.IsAbs(bin) {
		t.Fatalf("%s=%q, want absolute path", rustTransferBinEnv, bin)
	}
	if st, err := os.Stat(bin); err != nil {
		t.Skipf("Rust transfer example %s not found: %v", bin, err)
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("Rust transfer example %s is not executable", bin)
	}
	t.Logf("using Rust transfer example: %s", bin)
	return bin
}

func liveRustBinFromEnvOrRepo(env string, names ...string) (bin string, checked []string, ok bool) {
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
