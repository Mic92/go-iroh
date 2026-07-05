package iroh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const (
	defaultInitialStreamReceiveWindow     = 512 << 10
	defaultInitialConnectionReceiveWindow = 768 << 10
)

func TestQUICTransportConfigReceiveWindowsQLOG(t *testing.T) {
	tests := []struct {
		name       string
		config     *QUICTransportConfig
		wantStream uint64
		wantConn   uint64
	}{
		{
			name:       "zero",
			config:     &QUICTransportConfig{},
			wantStream: defaultInitialStreamReceiveWindow,
			wantConn:   defaultInitialConnectionReceiveWindow,
		},
		{
			name: "configured",
			config: &QUICTransportConfig{
				InitialStreamReceiveWindow:     8 << 20,
				MaxStreamReceiveWindow:         12 << 20,
				InitialConnectionReceiveWindow: 10 << 20,
				MaxConnectionReceiveWindow:     24 << 20,
			},
			wantStream: 8 << 20,
			wantConn:   10 << 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			qlogDir := t.TempDir()
			t.Setenv("QLOGDIR", qlogDir)

			client, server := transportConfigConnPair(t, ctx, "iroh-transport-config-qlog/"+tt.name, tt.config, tt.config)
			if err := client.CloseWithError(0, ""); err != nil {
				t.Fatalf("client close: %v", err)
			}
			if err := server.CloseWithError(0, ""); err != nil {
				t.Fatalf("server close: %v", err)
			}

			files, err := waitQLOGFiles(ctx, qlogDir, 2)
			if err != nil {
				t.Fatal(err)
			}
			params, err := readTransportParameters(files)
			if err != nil {
				t.Fatal(err)
			}
			assertTransportParameter(t, params, "local", tt.wantStream, tt.wantConn)
			assertTransportParameter(t, params, "remote", tt.wantStream, tt.wantConn)
		})
	}
}

func TestQUICTransportConfigLargeStreamTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	config := &QUICTransportConfig{
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         12 << 20,
		InitialConnectionReceiveWindow: 10 << 20,
		MaxConnectionReceiveWindow:     24 << 20,
	}
	client, server := transportConfigConnPair(t, ctx, "iroh-transport-config-large/0", config, config)
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	const size = 4 << 20
	done := make(chan error, 1)
	go func() {
		s, err := server.AcceptStream(ctx)
		if err != nil {
			done <- fmt.Errorf("accept stream: %w", err)
			return
		}
		if err := s.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			done <- fmt.Errorf("set read deadline: %w", err)
			return
		}
		n, err := io.Copy(io.Discard, s)
		if err != nil {
			done <- fmt.Errorf("copy stream: %w", err)
			return
		}
		if n != size {
			done <- fmt.Errorf("copied %d bytes, want %d", n, size)
			return
		}
		done <- nil
	}()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := s.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := io.Copy(s, bytes.NewReader(bytes.Repeat([]byte{0xa5}, size))); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := s.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func transportConfigConnPair(t *testing.T, ctx context.Context, alpn string, serverConfig, clientConfig *QUICTransportConfig) (client, server *Conn) {
	t.Helper()

	srvKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	serverOpts := []Option{
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	}
	if serverConfig != nil {
		serverOpts = append(serverOpts, WithTransportConfig(serverConfig))
	}
	srvEP, err := Bind(ctx, serverOpts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvEP.Shutdown(context.Background()) })

	clientOpts := []Option{WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))}
	if clientConfig != nil {
		clientOpts = append(clientOpts, WithTransportConfig(clientConfig))
	}
	clientEP, err := Bind(ctx, clientOpts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientEP.Shutdown(context.Background()) })

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := srvEP.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	addr := netaddr.NewEndpointAddr(srvEP.ID()).WithIP(srvEP.LocalAddr())
	client, err = clientEP.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	return client, res.conn
}

type transportParameter struct {
	file                               string
	initiator                          string
	initialMaxData                     uint64
	initialMaxStreamDataBidiLocal      uint64
	initialMaxStreamDataBidiRemote     uint64
	initialMaxStreamDataUnidirectional uint64
}

func readTransportParameters(files []string) ([]transportParameter, error) {
	var params []transportParameter
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := bytes.TrimPrefix(scanner.Bytes(), []byte{0x1e})
			var event map[string]any
			if err := json.Unmarshal(line, &event); err != nil {
				f.Close()
				return nil, fmt.Errorf("%s: parse qlog: %w", file, err)
			}
			if stringValue(event["name"]) != "transport:parameters_set" {
				continue
			}
			data := mapValue(event["data"])
			if data == nil {
				data = event
			}
			params = append(params, transportParameter{
				file:                               file,
				initiator:                          stringValue(data["initiator"]),
				initialMaxData:                     uint64Value(data["initial_max_data"]),
				initialMaxStreamDataBidiLocal:      uint64Value(data["initial_max_stream_data_bidi_local"]),
				initialMaxStreamDataBidiRemote:     uint64Value(data["initial_max_stream_data_bidi_remote"]),
				initialMaxStreamDataUnidirectional: uint64Value(data["initial_max_stream_data_uni"]),
			})
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: scan qlog: %w", file, err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return params, nil
}

func assertTransportParameter(t *testing.T, params []transportParameter, initiator string, wantStream, wantConn uint64) {
	t.Helper()
	for _, p := range params {
		if p.initiator != initiator {
			continue
		}
		if p.initialMaxStreamDataBidiLocal == wantStream && p.initialMaxData == wantConn {
			t.Logf("%s initiator=%s initial_max_stream_data_bidi_local=%d initial_max_data=%d", p.file, initiator, p.initialMaxStreamDataBidiLocal, p.initialMaxData)
			return
		}
	}
	t.Fatalf("transport parameters missing initiator=%q stream=%d conn=%d in %#v", initiator, wantStream, wantConn, params)
}

func mapValue(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func uint64Value(v any) uint64 {
	switch v := v.(type) {
	case float64:
		return uint64(v)
	case uint64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return uint64(n)
	default:
		return 0
	}
}
