package iroh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestTCPStreamTransportDialListen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tr, err := ListenTCPStreamTransport(77, "[::1]:0", TransportLinkLoopback)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		t.Fatal(err)
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
		ALPN:        "test/0",
		StableID:    1,
		TransportID: tr.ID(),
		Purpose:     "test",
		Nonce:       "nonce",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := tr.DialStream(ctx, addrs[0], StreamOptions{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server StreamAccept
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Conn.Close()
	if server.Token.Purpose != tok.Purpose || server.Token.TransportID != tok.TransportID {
		t.Fatalf("token = %+v, want %+v", server.Token, tok)
	}

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(server.Conn, server.Conn)
		done <- err
	}()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(client, buf[:]); err != nil {
		t.Fatal(err)
	}
	if string(buf[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", buf[:])
	}
	client.Close()
	server.Conn.Close()
	<-done
}

func TestTCPStreamTransportLocalAddrsCarryLinkClass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tr, err := ListenTCPStreamTransport(78, "[::1]:0", TransportLinkLoopback)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1", len(addrs))
	}
	got, err := ParseStreamLinkAddr(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != TransportLinkLoopback {
		t.Fatalf("class = %v, want %v", got.Class, TransportLinkLoopback)
	}
	if got.DialAddr == "" {
		t.Fatal("empty dial addr")
	}
}

func TestStreamOpenTokenBinaryRoundTrip(t *testing.T) {
	want := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "test/0",
		StableID:    7,
		TransportID: 11,
		Purpose:     "bulk",
		Nonce:       "nonce",
		Expiry:      time.Unix(0, 123456789),
	}
	var buf bytes.Buffer
	if err := writeStreamOpenToken(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readStreamOpenToken(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("token = %+v, want %+v", got, want)
	}
}

func TestStreamOpenTokenBinaryRejectsMalformed(t *testing.T) {
	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "test/0",
		StableID:    7,
		TransportID: 11,
		Purpose:     "bulk",
		Nonce:       "nonce",
		Expiry:      time.Unix(0, 123456789),
	}
	var buf bytes.Buffer
	if err := writeStreamOpenToken(&buf, tok); err != nil {
		t.Fatal(err)
	}
	good := buf.Bytes()

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bad version", append([]byte{streamOpenTokenVersion + 1}, good[1:]...)},
		{"truncated", good[:len(good)-1]},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readStreamOpenToken(bytes.NewReader(tt.data)); err == nil {
				t.Fatal("readStreamOpenToken succeeded, want error")
			}
		})
	}
}

func TestStreamOpenTokenBinaryLeavesPayloadUnread(t *testing.T) {
	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "test/0",
		StableID:    7,
		TransportID: 11,
		Purpose:     "bulk",
		Nonce:       "nonce",
		Expiry:      time.Unix(0, 123456789),
	}
	var buf bytes.Buffer
	if err := writeStreamOpenToken(&buf, tok); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("payload")
	if _, err := readStreamOpenToken(&buf); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "payload" {
		t.Fatalf("remaining bytes = %q, want payload", rest)
	}
}

func TestStreamOpenTokenBinaryRejectsOversizedString(t *testing.T) {
	err := writeStreamOpenToken(io.Discard, StreamOpenToken{
		LocalID: strings.Repeat("x", 1<<16),
	})
	if !errors.Is(err, errStreamTokenStringTooLong) {
		t.Fatalf("writeStreamOpenToken = %v, want errStreamTokenStringTooLong", err)
	}
}
