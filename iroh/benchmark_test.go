package iroh

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func benchmarkConnPair(b *testing.B, alpn string) (client, server *Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	b.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	srvEP, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srvEP.Shutdown(context.Background()) })

	clientEP, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { clientEP.Shutdown(context.Background()) })

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
		b.Fatalf("connect: %v", err)
	}

	res := <-done
	if res.err != nil {
		b.Fatalf("accept: %v", res.err)
	}
	b.Cleanup(func() {
		client.CloseWithError(0, "")
		res.conn.CloseWithError(0, "")
	})
	return client, res.conn
}

type benchConnStats struct {
	packetsSent     uint64
	packetsReceived uint64
	bytesSent       uint64
}

func snapshotConnStats(c *Conn) benchConnStats {
	s := c.qc.ConnectionStats()
	return benchConnStats{
		packetsSent:     s.PacketsSent,
		packetsReceived: s.PacketsReceived,
		bytesSent:       s.BytesSent,
	}
}

func reportConnStats(b *testing.B, client, server *Conn, clientStart, serverStart benchConnStats) {
	b.Helper()
	if b.N == 0 {
		return
	}
	clientEnd := snapshotConnStats(client)
	serverEnd := snapshotConnStats(server)
	packetsSent := (clientEnd.packetsSent - clientStart.packetsSent) + (serverEnd.packetsSent - serverStart.packetsSent)
	packetsReceived := (clientEnd.packetsReceived - clientStart.packetsReceived) + (serverEnd.packetsReceived - serverStart.packetsReceived)
	bytesSent := (clientEnd.bytesSent - clientStart.bytesSent) + (serverEnd.bytesSent - serverStart.bytesSent)
	b.ReportMetric(float64(packetsSent)/float64(b.N), "qpackets-sent/op")
	b.ReportMetric(float64(packetsReceived)/float64(b.N), "qpackets-recv/op")
	b.ReportMetric(float64(bytesSent)/float64(b.N), "qbytes-sent/op")
}

func reportConnCipher(b *testing.B, c *Conn) {
	b.Helper()
	b.ReportMetric(float64(c.qc.ConnectionState().TLS.CipherSuite), "cipher-suite")
}

func benchmarkQUICConnPair(b *testing.B, alpn string) (client, server *quic.Conn) {
	return benchmarkQUICConnPairWithConfig(b, alpn, &quic.Config{})
}

func benchmarkQUICConnPairWithConfig(b *testing.B, alpn string, conf *quic.Config) (client, server *quic.Conn) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	b.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	clientKey, _ := key.GenerateSecretKey()
	serverTLS, err := serverTLSConfig(srvKey, []string{alpn})
	if err != nil {
		b.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, srvKey.Public().EndpointID(), []string{alpn}, nil)
	if err != nil {
		b.Fatal(err)
	}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { serverUDP.Close() })
	ln, err := quic.Listen(serverUDP, serverTLS, conf)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn *quic.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { clientUDP.Close() })
	client, err = quic.Dial(ctx, clientUDP, ln.Addr(), clientTLS, conf)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	res := <-done
	if res.err != nil {
		b.Fatalf("accept: %v", res.err)
	}
	b.Cleanup(func() {
		client.CloseWithError(0, "")
		res.conn.CloseWithError(0, "")
	})
	return client, res.conn
}

func snapshotQUICConnStats(c *quic.Conn) benchConnStats {
	s := c.ConnectionStats()
	return benchConnStats{
		packetsSent:     s.PacketsSent,
		packetsReceived: s.PacketsReceived,
		bytesSent:       s.BytesSent,
	}
}

func reportQUICConnStats(b *testing.B, client, server *quic.Conn, clientStart, serverStart benchConnStats) {
	b.Helper()
	if b.N == 0 {
		return
	}
	clientEnd := snapshotQUICConnStats(client)
	serverEnd := snapshotQUICConnStats(server)
	packetsSent := (clientEnd.packetsSent - clientStart.packetsSent) + (serverEnd.packetsSent - serverStart.packetsSent)
	packetsReceived := (clientEnd.packetsReceived - clientStart.packetsReceived) + (serverEnd.packetsReceived - serverStart.packetsReceived)
	bytesSent := (clientEnd.bytesSent - clientStart.bytesSent) + (serverEnd.bytesSent - serverStart.bytesSent)
	b.ReportMetric(float64(packetsSent)/float64(b.N), "qpackets-sent/op")
	b.ReportMetric(float64(packetsReceived)/float64(b.N), "qpackets-recv/op")
	b.ReportMetric(float64(bytesSent)/float64(b.N), "qbytes-sent/op")
}

func BenchmarkConnStreamPingPong(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-ping-pong/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		for {
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := peer.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
	b.StopTimer()
	reportConnStats(b, client, server, clientStart, serverStart)
	reportConnCipher(b, client)
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
}

func BenchmarkConnStreamPingPongPhases(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-ping-pong-phases/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	type phaseTotals struct {
		read  time.Duration
		write time.Duration
	}
	phases := make(chan phaseTotals, 1)
	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		var totals phaseTotals
		for {
			t0 := time.Now()
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				phases <- totals
				done <- err
				return
			}
			t1 := time.Now()
			if _, err := peer.Write(buf[:]); err != nil {
				phases <- totals
				done <- err
				return
			}
			t2 := time.Now()
			totals.read += t1.Sub(t0)
			totals.write += t2.Sub(t1)
		}
	}()

	var buf [1]byte
	var writeTotal, readTotal time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		t1 := time.Now()
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
		t2 := time.Now()
		writeTotal += t1.Sub(t0)
		readTotal += t2.Sub(t1)
	}
	b.StopTimer()
	if b.N > 0 {
		b.ReportMetric(float64(writeTotal.Nanoseconds())/float64(b.N), "write-ns/op")
		b.ReportMetric(float64(readTotal.Nanoseconds())/float64(b.N), "read-ns/op")
	}
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
	serverPhases := <-phases
	if b.N > 0 {
		b.ReportMetric(float64(serverPhases.read.Nanoseconds())/float64(b.N), "server-read-ns/op")
		b.ReportMetric(float64(serverPhases.write.Nanoseconds())/float64(b.N), "server-write-ns/op")
	}
}

func BenchmarkConnStreamThroughput(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	if err := s.Close(); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			b.Fatalf("copy: %v", err)
		}
	case <-time.After(10 * time.Second):
		s.CancelRead(0)
		s.CancelWrite(0)
		b.Fatalf("copy did not finish after stream close")
	}
	reportConnStats(b, client, server, clientStart, serverStart)
	reportConnCipher(b, client)
}

func BenchmarkQUICRawUDPStreamPingPong(b *testing.B) {
	client, server := benchmarkQUICConnPair(b, "iroh-bench-raw-quic-ping-pong/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		var buf [1]byte
		for {
			if _, err := io.ReadFull(peer, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := peer.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	clientStart := snapshotQUICConnStats(client)
	serverStart := snapshotQUICConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf[:]); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(s, buf[:]); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
	b.StopTimer()
	reportQUICConnStats(b, client, server, clientStart, serverStart)
	s.CancelRead(0)
	s.CancelWrite(0)
	<-done
}

func BenchmarkQUICRawUDPStreamThroughput(b *testing.B) {
	client, server := benchmarkQUICConnPair(b, "iroh-bench-raw-quic-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotQUICConnStats(client)
	serverStart := snapshotQUICConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(buf); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	if err := s.Close(); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	if err := <-done; err != nil {
		b.Fatalf("copy: %v", err)
	}
	reportQUICConnStats(b, client, server, clientStart, serverStart)
}

func BenchmarkConnDatagramPingPong(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-datagram-ping-pong/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		for {
			p, err := server.ReadDatagram(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := server.SendDatagram(p); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := []byte{0}
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.SendDatagram(buf); err != nil {
			b.Fatalf("send datagram: %v", err)
		}
		if _, err := client.ReadDatagram(ctx); err != nil {
			b.Fatalf("read datagram: %v", err)
		}
	}
	b.StopTimer()
	reportConnStats(b, client, server, clientStart, serverStart)
	client.CloseWithError(0, "")
	<-done
}

func BenchmarkConnDatagramThroughput(b *testing.B) {
	client, server := benchmarkConnPair(b, "iroh-bench-datagram-throughput/0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		for {
			p, err := server.ReadDatagram(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := server.SendDatagram(p); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	clientStart := snapshotConnStats(client)
	serverStart := snapshotConnStats(server)
	b.ResetTimer()
	const window = 32
	var sent, received int
	for received < b.N {
		for sent < b.N && sent-received < window {
			if err := client.SendDatagram(buf); err != nil {
				b.Fatalf("send datagram: %v", err)
			}
			sent++
		}
		if _, err := client.ReadDatagram(ctx); err != nil {
			b.Fatalf("read datagram: %v", err)
		}
		received++
	}
	b.StopTimer()
	reportConnStats(b, client, server, clientStart, serverStart)
	client.CloseWithError(0, "")
	<-done
}

func benchmarkTCPConnPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn net.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		done <- accepted{conn: c, err: err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial tcp: %v", err)
	}
	res := <-done
	if res.err != nil {
		b.Fatalf("accept tcp: %v", res.err)
	}
	b.Cleanup(func() {
		client.Close()
		res.conn.Close()
	})
	return client, res.conn
}

func BenchmarkRawTCPConnPingPong(b *testing.B) {
	client, server := benchmarkTCPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			if _, err := io.ReadFull(server, buf[:]); err != nil {
				done <- err
				return
			}
			if _, err := server.Write(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf[:]); err != nil {
			b.Fatalf("write tcp: %v", err)
		}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read tcp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawTCPConnThroughput(b *testing.B) {
	client, server := benchmarkTCPConnPair(b)

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write tcp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	if err := <-done; err != nil {
		b.Fatalf("copy tcp: %v", err)
	}
}

func BenchmarkTCPStreamTransportThroughput(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tr, err := ListenTCPStreamTransport(101, "[::1]:0", TransportLinkLoopback)
	if err != nil {
		b.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		b.Fatal(err)
	}

	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- tr.ListenStreams(ctx, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()

	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "bench/0",
		StableID:    1,
		TransportID: tr.ID(),
		Purpose:     "throughput",
		Nonce:       "bench",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := tr.DialStream(ctx, addrs[0], StreamOptions{Token: tok})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case a := <-accepted:
		server = a.Conn
	case err := <-errc:
		b.Fatal(err)
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()
	var cleanupOnce sync.Once
	cleanup := func() {
		client.Close()
		server.Close()
		<-done
	}
	b.Cleanup(func() { cleanupOnce.Do(cleanup) })

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write tcp stream: %v", err)
		}
	}
	b.StopTimer()
	cleanupOnce.Do(cleanup)
}

func BenchmarkStreamLinkSelection(b *testing.B) {
	local := []netaddr.CustomAddr{
		NewStreamLinkAddr(101, TransportLinkWiFiLAN, "wlan0", "192.0.2.11:1"),
		NewStreamLinkAddr(101, TransportLinkWiredLAN, "en0", "192.0.2.10:1"),
		NewStreamLinkAddr(101, TransportLinkThunderbolt, "bridge0", "[fe80::1%bridge0]:1"),
	}
	remote := []netaddr.CustomAddr{
		NewStreamLinkAddr(101, TransportLinkLAN, "utun0", "198.51.100.20:1"),
		NewStreamLinkAddr(101, TransportLinkWiredLAN, "en0", "192.0.2.20:1"),
		NewStreamLinkAddr(101, TransportLinkThunderbolt, "bridge0", "[fe80::2%bridge0]:1"),
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, ok := SelectStreamLink(local, remote)
		if !ok {
			b.Fatal("SelectStreamLink failed")
		}
		if got.Class != TransportLinkThunderbolt {
			b.Fatalf("class = %v, want %v", got.Class, TransportLinkThunderbolt)
		}
	}
}

func BenchmarkPreferredTransportLink(b *testing.B) {
	local := []TransportLinkClass{
		TransportLinkWiFiLAN,
		TransportLinkWiredLAN,
		TransportLinkThunderbolt,
		TransportLinkRDMA,
	}
	remote := []TransportLinkClass{
		TransportLinkLAN,
		TransportLinkWiredLAN,
		TransportLinkThunderbolt,
		TransportLinkRDMA,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got := PreferredTransportLink(local, remote)
		if got != TransportLinkRDMA {
			b.Fatalf("class = %v, want %v", got, TransportLinkRDMA)
		}
	}
}

func BenchmarkTCPStreamTransportNegotiatedThroughput(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tr, err := ListenTCPStreamTransport(102, "[::1]:0", TransportLinkLoopback)
	if err != nil {
		b.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		b.Fatal(err)
	}
	selected, ok := SelectStreamLink(addrs, addrs)
	if !ok {
		b.Fatal("SelectStreamLink failed")
	}

	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- tr.ListenStreams(ctx, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()

	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "bench/0",
		StableID:    1,
		TransportID: tr.ID(),
		Purpose:     "throughput",
		Nonce:       "bench",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := tr.DialStream(ctx, selected.Remote, StreamOptions{Token: tok})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case a := <-accepted:
		server = a.Conn
	case err := <-errc:
		b.Fatal(err)
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()
	var cleanupOnce sync.Once
	cleanup := func() {
		client.Close()
		server.Close()
		<-done
	}
	b.Cleanup(func() { cleanupOnce.Do(cleanup) })

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write negotiated tcp stream: %v", err)
		}
	}
	b.StopTimer()
	cleanupOnce.Do(cleanup)
}

func BenchmarkTCPStreamTransportLiveNegotiatedThroughput(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	bind, ok := benchmarkThunderboltBindAddr(b)
	if !ok {
		b.Skip("no live thunderbolt address")
	}
	tr, err := ListenTCPStreamTransport(103, bind, TransportLinkThunderbolt)
	if err != nil {
		b.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		b.Fatal(err)
	}
	selected, ok := SelectStreamLink(addrs, addrs)
	if !ok {
		b.Fatal("SelectStreamLink failed")
	}
	if selected.Class != TransportLinkThunderbolt {
		b.Skipf("selected %s, want live thunderbolt", selected.Class)
	}

	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- tr.ListenStreams(ctx, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()

	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "bench/0",
		StableID:    1,
		TransportID: tr.ID(),
		Purpose:     "throughput",
		Nonce:       "bench",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := tr.DialStream(ctx, selected.Remote, StreamOptions{Token: tok})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case a := <-accepted:
		server = a.Conn
	case err := <-errc:
		b.Fatal(err)
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()
	var cleanupOnce sync.Once
	cleanup := func() {
		client.Close()
		server.Close()
		<-done
	}
	b.Cleanup(func() { cleanupOnce.Do(cleanup) })

	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write live negotiated tcp stream: %v", err)
		}
	}
	b.StopTimer()
	cleanupOnce.Do(cleanup)
}

func benchmarkThunderboltBindAddr(b *testing.B) (string, bool) {
	b.Helper()
	links, err := LocalTransportLinkAddrs()
	if err != nil {
		b.Fatal(err)
	}
	for _, link := range links {
		if link.Class != TransportLinkThunderbolt {
			continue
		}
		ip, ok := addrIP(link.Addr)
		if ok && ip.To4() != nil {
			return net.JoinHostPort(ip.String(), "0"), true
		}
	}
	for _, link := range links {
		if link.Class != TransportLinkThunderbolt {
			continue
		}
		if addr, ok := tcpDialAddrFromLinkAddr(link, 0); ok {
			return addr, true
		}
	}
	return "", false
}

func benchmarkUDPConnPair(b *testing.B) (client, server *net.UDPConn) {
	b.Helper()
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { server.Close() })

	client, err = net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial udp: %v", err)
	}
	b.Cleanup(func() { client.Close() })
	return client, server
}

func benchmarkUnconnectedUDPConnPair(b *testing.B) (client, server *net.UDPConn, serverAddr netip.AddrPort) {
	b.Helper()
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { server.Close() })
	client, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { client.Close() })
	return client, server, server.LocalAddr().(*net.UDPAddr).AddrPort()
}

func BenchmarkRawUDPPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if _, err := server.WriteToUDPAddrPort(buf[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf[:]); err != nil {
			b.Fatalf("write udp: %v", err)
		}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  [1]byte
	}
	writes := make(chan writeReq, 16)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf[:], req.addr)
			} else {
				_, err = req.conn.Write(req.buf[:])
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			writes <- writeReq{conn: server, addr: addr, buf: buf}
		}
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, buf: buf}
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPFullyQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	type datagram struct {
		addr netip.AddrPort
		buf  [1]byte
	}
	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  [1]byte
	}

	clientReads := make(chan datagram, 16)
	serverReads := make(chan datagram, 16)
	readLoop := func(conn *net.UDPConn, out chan<- datagram, done chan<- error) {
		var buf [1]byte
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			out <- datagram{addr: addr, buf: buf}
		}
	}

	clientReadDone := make(chan error, 1)
	serverReadDone := make(chan error, 1)
	go readLoop(client, clientReads, clientReadDone)
	go readLoop(server, serverReads, serverReadDone)

	writes := make(chan writeReq, 16)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf[:], req.addr)
			} else {
				_, err = req.conn.Write(req.buf[:])
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	serverDone := make(chan error, 1)
	go func() {
		for d := range serverReads {
			writes <- writeReq{conn: server, addr: d.addr, buf: d.buf}
		}
		serverDone <- nil
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, buf: buf}
		<-clientReads
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-clientReadDone
	<-serverReadDone
	close(serverReads)
	<-serverDone
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPMagicQueuedPingPong(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)
	benchmarkRawUDPMagicQueuedPingPong(b, client, server, netip.AddrPort{})
}

func BenchmarkRawUDPUnconnectedMagicQueuedPingPong(b *testing.B) {
	client, server, serverAddr := benchmarkUnconnectedUDPConnPair(b)
	benchmarkRawUDPMagicQueuedPingPong(b, client, server, serverAddr)
}

func benchmarkRawUDPMagicQueuedPingPong(b *testing.B, client, server *net.UDPConn, clientWriteAddr netip.AddrPort) {

	type datagram struct {
		addr netip.AddrPort
		buf  []byte
	}
	type writeReq struct {
		conn *net.UDPConn
		addr netip.AddrPort
		buf  []byte
	}

	const (
		recvDepth = 4
		bufSize   = 1452 + 512
	)

	pool := make(chan []byte, 1024)
	getBuf := func() []byte {
		select {
		case buf := <-pool:
			return buf
		default:
			return make([]byte, bufSize)
		}
	}
	putBuf := func(buf []byte) {
		select {
		case pool <- buf[:bufSize]:
		default:
		}
	}

	readLoop := func(conn *net.UDPConn, out chan<- datagram, done chan<- error) {
		for {
			buf := getBuf()
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				putBuf(buf)
				done <- err
				return
			}
			out <- datagram{addr: addr, buf: buf[:n]}
		}
	}

	clientReads := make(chan datagram, recvDepth)
	serverReads := make(chan datagram, recvDepth)
	clientReadDone := make(chan error, 1)
	serverReadDone := make(chan error, 1)
	go readLoop(client, clientReads, clientReadDone)
	go readLoop(server, serverReads, serverReadDone)

	writes := make(chan writeReq, 64)
	writerDone := make(chan error, 1)
	go func() {
		for req := range writes {
			var err error
			if req.addr.IsValid() {
				_, err = req.conn.WriteToUDPAddrPort(req.buf, req.addr)
			} else {
				_, err = req.conn.Write(req.buf)
			}
			if err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	serverDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		for d := range serverReads {
			if len(d.buf) != 1 {
				putBuf(d.buf)
				serverDone <- io.ErrShortBuffer
				return
			}
			copy(buf[:], d.buf)
			putBuf(d.buf)
			writes <- writeReq{conn: server, addr: d.addr, buf: buf[:]}
		}
		serverDone <- nil
	}()

	var buf [1]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes <- writeReq{conn: client, addr: clientWriteAddr, buf: buf[:]}
		d := <-clientReads
		copy(buf[:], d.buf)
		putBuf(d.buf)
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-clientReadDone
	<-serverReadDone
	close(serverReads)
	<-serverDone
	close(writes)
	if err := <-writerDone; err != nil {
		b.Fatalf("write udp: %v", err)
	}
}

func BenchmarkRawUDPThroughput(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)
	b.Cleanup(func() { client.SetReadDeadline(time.Now()) })

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			n, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			if _, err := server.WriteToUDPAddrPort(buf[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write udp: %v", err)
		}
		if _, err := io.ReadFull(client, buf); err != nil {
			b.Fatalf("read udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPSendThroughput(b *testing.B) {
	client, server := benchmarkUDPConnPair(b)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := server.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(buf); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPUnconnectedSendThroughput(b *testing.B) {
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		client.Close()
		b.Fatal(err)
	}
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := server.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteToUDPAddrPort(buf, serverAddr); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawUDPUnconnectedAckedSendThroughput(b *testing.B) {
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		client.Close()
		b.Fatal(err)
	}
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		var ack [1]byte
		var nrecv int
		for {
			_, addr, err := server.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			nrecv++
			if nrecv%10 == 0 {
				if _, err := server.WriteToUDPAddrPort(ack[:], addr); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	ackDone := make(chan error, 1)
	go func() {
		var ack [1]byte
		for {
			if _, _, err := client.ReadFromUDPAddrPort(ack[:]); err != nil {
				ackDone <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteToUDPAddrPort(buf, serverAddr); err != nil {
			b.Fatalf("write udp: %v", err)
		}
	}
	b.StopTimer()
	client.Close()
	server.Close()
	<-done
	<-ackDone
}

func BenchmarkRawMagicConnSendThroughput(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, clientUDP)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			if _, _, err := serverUDP.ReadFromUDPAddrPort(buf[:]); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	addr := serverUDP.LocalAddr()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := magic.WriteTo(buf, addr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
	}
	b.StopTimer()
	magic.Close()
	serverUDP.Close()
	<-done
}

func BenchmarkRawMagicConnAckedSendThroughput(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, clientUDP)
	ctx, cancel := context.WithCancel(context.Background())
	go magic.Serve(ctx)

	done := make(chan error, 1)
	go func() {
		var buf [1200]byte
		var ack [1]byte
		var nrecv int
		for {
			_, addr, err := serverUDP.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				done <- err
				return
			}
			nrecv++
			if nrecv%10 == 0 {
				if _, err := serverUDP.WriteToUDPAddrPort(ack[:], addr); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	ackDone := make(chan error, 1)
	go func() {
		var ack [1]byte
		for {
			if _, _, err := magic.ReadFrom(ack[:]); err != nil {
				ackDone <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	addr := serverUDP.LocalAddr()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := magic.WriteTo(buf, addr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	magic.Close()
	serverUDP.Close()
	<-done
	<-ackDone
}

func BenchmarkRawMagicConnPingPong(b *testing.B) {
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		clientUDP.Close()
		b.Fatal(err)
	}

	clientSock := socket.NewSocket()
	serverSock := socket.NewSocket()
	client := socket.NewMagicConn(clientSock, clientUDP)
	server := socket.NewMagicConn(serverSock, serverUDP)
	ctx, cancel := context.WithCancel(context.Background())
	go client.Serve(ctx)
	go server.Serve(ctx)

	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		for {
			n, addr, err := server.ReadFrom(buf[:])
			if err != nil {
				done <- err
				return
			}
			if n != 1 {
				done <- io.ErrShortBuffer
				return
			}
			if _, err := server.WriteTo(buf[:], addr); err != nil {
				done <- err
				return
			}
		}
	}()

	var buf [1]byte
	serverAddr := serverUDP.LocalAddr()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.WriteTo(buf[:], serverAddr); err != nil {
			b.Fatalf("write magic: %v", err)
		}
		if _, _, err := client.ReadFrom(buf[:]); err != nil {
			b.Fatalf("read magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	client.Close()
	server.Close()
	<-done
}

func BenchmarkRawMagicConnReceiveThroughput(b *testing.B) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		udp.Close()
		b.Fatal(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, udp)
	ctx, cancel := context.WithCancel(context.Background())
	go magic.Serve(ctx)

	done := make(chan error, 1)
	payload := make([]byte, 1200)
	dst := udp.LocalAddr()
	go func() {
		for {
			if _, err := sender.WriteTo(payload, dst); err != nil {
				done <- err
				return
			}
		}
	}()

	buf := make([]byte, 1200)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := magic.ReadFrom(buf); err != nil {
			b.Fatalf("read magic: %v", err)
		}
	}
	b.StopTimer()
	cancel()
	magic.Close()
	sender.Close()
	<-done
}
