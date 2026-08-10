package iroh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/sys/unix"
)

var workloadMessageSizes = [...]int{32, 256, 1024}

const defaultWorkloadScalingBytes = 64 << 20

func TestWorkloadSocketConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Bind(ctx, WithSecretKey(serverKey), WithALPNs("iroh-workload-config/0"),
		WithTransportConfig(&QUICTransportConfig{InitialPacketSize: 1200, MaxIncomingStreams: 64}),
		WithBindAddr(netip.AddrPortFrom(workloadIPv4(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	client, err := Bind(ctx,
		WithTransportConfig(&QUICTransportConfig{InitialPacketSize: 1200, MaxIncomingStreams: 64}),
		WithBindAddr(netip.AddrPortFrom(workloadIPv4(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())
	accepted := make(chan acceptedConn, 1)
	go func() {
		conn, err := server.Accept(ctx)
		accepted <- acceptedConn{conn: conn, err: err}
	}()
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, "iroh-workload-config/0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	serverConn := <-accepted
	if serverConn.err != nil {
		t.Fatal(serverConn.err)
	}
	defer serverConn.conn.CloseWithError(0, "")
	receive, send := workloadEndpointBuffers(t, client)
	serverReceive, serverSend := workloadEndpointBuffers(t, server)
	t.Logf("initial_packet_size=1200 max_incoming_streams=64 requested_receive_buffer=7340032 requested_send_buffer=7340032 client_receive_buffer=%d client_send_buffer=%d server_receive_buffer=%d server_send_buffer=%d loopback=127.0.0.1 congestion_control=cubic", receive, send, serverReceive, serverSend)
}

func workloadEndpointBuffers(t *testing.T, endpoint *Endpoint) (receive, send int) {
	t.Helper()
	raw, err := endpoint.magic.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	receive, err = workloadSocketBuffer(raw, unix.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	send, err = workloadSocketBuffer(raw, unix.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	return receive, send
}

func workloadSocketBuffer(raw syscall.RawConn, option int) (int, error) {
	var value int
	var socketErr error
	err := raw.Control(func(fd uintptr) {
		value, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option)
	})
	if err != nil {
		return 0, err
	}
	return value, socketErr
}

func BenchmarkConnStreamScaling(b *testing.B) {
	for _, streams := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
			client, server := benchmarkConnPairAddr(b, "iroh-workload-stream-scaling/0", workloadIPv4())
			benchmarkConnDownloadFlows(b, []*Conn{client}, []*Conn{server}, streams)
		})
	}
}

func BenchmarkConnConnectionScaling(b *testing.B) {
	for _, connections := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("connections=%d", connections), func(b *testing.B) {
			clients, servers := benchmarkConnFanout(b, connections)
			benchmarkConnDownloadFlows(b, clients, servers, 1)
		})
	}
}

func benchmarkConnFanout(b *testing.B, connections int) (clients, servers []*Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)
	const alpn = "iroh-workload-connection-scaling/0"
	transportConfig := WithTransportConfig(&QUICTransportConfig{InitialPacketSize: 1200, MaxIncomingStreams: 64})
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}
	serverEndpoint, err := Bind(ctx, WithSecretKey(serverKey), WithALPNs(alpn), transportConfig,
		WithBindAddr(netip.AddrPortFrom(workloadIPv4(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { serverEndpoint.Shutdown(context.Background()) })
	accepted := make(chan acceptedConn, connections)
	go func() {
		for range connections {
			conn, err := serverEndpoint.Accept(ctx)
			accepted <- acceptedConn{conn, err}
		}
	}()
	addr := netaddr.NewEndpointAddr(serverEndpoint.ID()).WithIP(serverEndpoint.LocalAddr())
	for range connections {
		clientEndpoint, err := Bind(ctx, transportConfig, WithBindAddr(netip.AddrPortFrom(workloadIPv4(), 0)))
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { clientEndpoint.Shutdown(context.Background()) })
		client, err := clientEndpoint.Connect(ctx, addr, alpn)
		if err != nil {
			b.Fatal(err)
		}
		clients = append(clients, client)
	}
	for range connections {
		result := <-accepted
		if result.err != nil {
			b.Fatal(result.err)
		}
		servers = append(servers, result.conn)
	}
	return clients, servers
}

type acceptedConn struct {
	conn *Conn
	err  error
}

func benchmarkConnDownloadFlows(b *testing.B, clients, servers []*Conn, streamsPerConn int) {
	b.Helper()
	if b.N != 1 {
		b.Fatalf("scaling benchmark requires -benchtime=1x; b.N=%d", b.N)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	flows := len(clients) * streamsPerConn
	totalBytes := workloadScalingBytes(b)
	bytesPerFlow := totalBytes / int64(flows)
	serverDone := make(chan error, flows)
	for _, server := range servers {
		go benchmarkConnDownloadServer(ctx, server, streamsPerConn, bytesPerFlow, serverDone)
	}
	flowDurationNS := make([]int64, flows)
	flowBytes := make([]int64, flows)
	flowErr := make([]error, flows)
	var wg sync.WaitGroup
	wg.Add(flows)
	b.SetBytes(totalBytes)
	b.ReportAllocs()
	cpuStart := readBenchmarkCPUTime(b)
	b.ResetTimer()
	flow := 0
	for _, client := range clients {
		for range streamsPerConn {
			i := flow
			flow++
			go func(client *Conn) {
				defer wg.Done()
				start := time.Now()
				stream, err := client.OpenStreamSync(ctx)
				if err == nil {
					_, err = stream.Write([]byte{1})
				}
				var n int64
				if err == nil {
					n, err = io.CopyN(io.Discard, stream, bytesPerFlow)
				}
				flowErr[i] = err
				flowBytes[i] = n
				flowDurationNS[i] = time.Since(start).Nanoseconds()
			}(client)
		}
	}
	wg.Wait()
	for i, err := range flowErr {
		if err != nil {
			b.Errorf("flow %d: %v", i, err)
		}
	}
	for range flows {
		if err := <-serverDone; err != nil {
			b.Errorf("server flow: %v", err)
		}
	}
	b.StopTimer()
	rung := fmt.Sprintf("full-scale-streams-%d-connections-%d", streamsPerConn, len(clients))
	emitLayerLadderSampleRecord(b, layerLadderSample{
		Rung:           rung,
		Bytes:          totalBytes,
		FlowBytes:      flowBytes,
		FlowDurationNS: flowDurationNS,
	}, cpuStart)
}

func workloadScalingBytes(b *testing.B) int64 {
	b.Helper()
	value := os.Getenv("IROH_WORKLOAD_SCALING_BYTES")
	if value == "" {
		return defaultWorkloadScalingBytes
	}
	bytes, err := strconv.ParseInt(value, 10, 64)
	if err != nil || bytes <= 0 {
		b.Fatalf("invalid IROH_WORKLOAD_SCALING_BYTES %q", value)
	}
	return bytes
}

func benchmarkConnDownloadServer(ctx context.Context, server *Conn, streams int, bytes int64, done chan<- error) {
	for i := range streams {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			for range streams - i {
				done <- err
			}
			return
		}
		go func() {
			var request [1]byte
			_, err := io.ReadFull(stream, request[:])
			if err == nil {
				_, err = io.CopyN(stream, layerLadderZeroReader{}, bytes)
			}
			if err == nil {
				err = stream.Close()
			}
			done <- err
		}()
	}
}

func BenchmarkRawTCPMessageRate(b *testing.B) {
	for _, size := range workloadMessageSizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			client, server := benchmarkTCPConnPair(b)
			done := make(chan error, 1)
			go func() {
				if _, err := io.CopyN(io.Discard, server, int64(b.N*size)); err != nil {
					done <- err
					return
				}
				_, err := server.Write([]byte{1})
				done <- err
			}()
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			cpuStart := readBenchmarkCPUTime(b)
			b.ResetTimer()
			for range b.N {
				if _, err := client.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
			var ack [1]byte
			if _, err := io.ReadFull(client, ack[:]); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			emitWorkloadSample(b, fmt.Sprintf("tcp-stream-msg-%d", size), size, cpuStart)
		})
	}
}

func BenchmarkQUICMessageRate(b *testing.B) {
	for _, size := range workloadMessageSizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			client, server := benchmarkQUICConnPairWithConfig(b, "iroh-workload-qng-message/0", &quic.Config{InitialPacketSize: 1200})
			benchmarkQUICMessages(b, client, server, size, fmt.Sprintf("quic-stream-msg-%d", size))
		})
	}
}

func BenchmarkConnMessageRate(b *testing.B) {
	for _, size := range workloadMessageSizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			client, server := benchmarkConnPairAddr(b, "iroh-workload-conn-message/0", workloadIPv4())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				peer, err := server.AcceptStream(ctx)
				if err == nil {
					_, err = io.CopyN(io.Discard, peer, int64(b.N*size))
				}
				if err == nil {
					_, err = peer.Write([]byte{1})
				}
				done <- err
			}()
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			cpuStart := readBenchmarkCPUTime(b)
			b.ResetTimer()
			for range b.N {
				if _, err := stream.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
			var ack [1]byte
			if _, err := io.ReadFull(stream, ack[:]); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			emitWorkloadSample(b, fmt.Sprintf("full-stream-msg-%d", size), size, cpuStart)
		})
	}
}

func benchmarkQUICMessages(b *testing.B, client, server *quic.Conn, size int, rung string) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err == nil {
			_, err = io.CopyN(io.Discard, peer, int64(b.N*size))
		}
		if err == nil {
			_, err = peer.Write([]byte{1})
		}
		done <- err
	}()
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	cpuStart := readBenchmarkCPUTime(b)
	b.ResetTimer()
	for range b.N {
		if _, err := stream.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	emitWorkloadSample(b, rung, size, cpuStart)
}

func BenchmarkRawUDPMessageRate(b *testing.B) {
	for _, size := range workloadMessageSizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			client, server := benchmarkUDPConnPair(b)
			benchmarkUDPMessageEcho(b, client, server, size, fmt.Sprintf("udp-datagram-msg-%d", size))
		})
	}
}

func BenchmarkConnDatagramMessageRate(b *testing.B) {
	for _, size := range workloadMessageSizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			client, server := benchmarkConnPairAddr(b, "iroh-workload-conn-datagram/0", workloadIPv4())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				for sequence := 0; sequence < b.N; {
					p, err := server.ReadDatagram(ctx)
					if err != nil {
						done <- err
						return
					}
					if err := server.SendDatagram(p); err != nil {
						done <- err
						return
					}
					if len(p) >= 8 && binary.BigEndian.Uint64(p) == uint64(sequence) {
						sequence++
					}
				}
				done <- nil
			}()
			buf := make([]byte, size)
			echoes := make(chan []byte, 1)
			receiveErr := make(chan error, 1)
			go func() {
				for {
					got, err := client.ReadDatagram(ctx)
					if err != nil {
						select {
						case receiveErr <- err:
						case <-ctx.Done():
						}
						return
					}
					select {
					case echoes <- got:
					case <-ctx.Done():
						return
					}
				}
			}()
			retry := time.NewTimer(time.Hour)
			if !retry.Stop() {
				<-retry.C
			}
			defer retry.Stop()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			cpuStart := readBenchmarkCPUTime(b)
			b.ResetTimer()
			for sequence := range b.N {
				binary.BigEndian.PutUint64(buf, uint64(sequence))
				if err := client.SendDatagram(buf); err != nil {
					b.Fatal(err)
				}
				retry.Reset(100 * time.Millisecond)
			awaitEcho:
				for {
					select {
					case got := <-echoes:
						if len(got) >= 8 && binary.BigEndian.Uint64(got) == uint64(sequence) {
							if !retry.Stop() {
								<-retry.C
							}
							break awaitEcho
						}
					case err := <-receiveErr:
						b.Fatal(err)
					case <-retry.C:
						if err := client.SendDatagram(buf); err != nil {
							b.Fatal(err)
						}
						retry.Reset(100 * time.Millisecond)
					}
				}
			}
			b.StopTimer()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			emitWorkloadSample(b, fmt.Sprintf("full-datagram-msg-%d", size), size, cpuStart)
		})
	}
}

func benchmarkUDPMessageEcho(b *testing.B, client, server *net.UDPConn, size int, rung string) {
	b.Helper()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, size)
		for range b.N {
			n, addr, err := server.ReadFromUDP(buf)
			if err == nil {
				_, err = server.WriteToUDP(buf[:n], addr)
			}
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	cpuStart := readBenchmarkCPUTime(b)
	b.ResetTimer()
	for range b.N {
		if _, err := client.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	emitWorkloadSample(b, rung, size, cpuStart)
}

func emitWorkloadSample(b *testing.B, rung string, size int, cpuStart benchmarkCPUTime) {
	b.Helper()
	emitLayerLadderSampleRecord(b, layerLadderSample{
		Rung:     rung,
		Bytes:    int64(b.N * size),
		Messages: int64(b.N),
	}, cpuStart)
}

func workloadIPv4() netip.Addr {
	return netip.MustParseAddr("127.0.0.1")
}
