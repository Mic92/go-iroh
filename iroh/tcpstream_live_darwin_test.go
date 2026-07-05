//go:build darwin

package iroh

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

func TestTCPStreamTransportLiveAppleFastLinkDialListen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr, err := ListenTCPStreamTransport(179, "[::]:0", TransportLinkLAN)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	addrs, err := tr.LocalAddrs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hasStreamLinkInterface(addrs, "en1") || hasStreamLinkInterface(addrs, "en2") || hasStreamLinkInterface(addrs, "en3") {
		t.Fatalf("advertised numbered Thunderbolt member link: %v", streamLinkStrings(addrs))
	}
	if !hasStreamLinkClass(addrs, TransportLinkWAN) {
		t.Skipf("no live WAN candidate: %v", streamLinkStrings(addrs))
	}
	if !hasStreamLinkClass(addrs, TransportLinkAWDL) {
		t.Skipf("no live AWDL candidate: %v", streamLinkStrings(addrs))
	}

	selected, ok := SelectStreamLink(addrs, addrs)
	if !ok {
		t.Fatal("SelectStreamLink failed")
	}
	link, err := ParseStreamLinkAddr(selected.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Class != TransportLinkThunderbolt || link.Interface != "bridge0" {
		t.Skipf("selected %s on %s, want live Thunderbolt Bridge from %v", selected.Class, link.Interface, streamLinkStrings(addrs))
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
		LocalID:     "local",
		RemoteID:    "remote",
		ALPN:        "apple-live/0",
		StableID:    1,
		TransportID: tr.ID(),
		Purpose:     "live-apple-fast-link",
		Nonce:       "nonce",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := tr.DialStream(ctx, selected.Remote, StreamOptions{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case a := <-accepted:
		server = a.Conn
		if a.Token.Purpose != tok.Purpose || a.Token.TransportID != tok.TransportID {
			t.Fatalf("token = %+v, want %+v", a.Token, tok)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var buf [2]byte
	if _, err := io.ReadFull(server, buf[:]); err != nil {
		t.Fatal(err)
	}
	if string(buf[:]) != "ok" {
		t.Fatalf("payload = %q, want ok", buf[:])
	}
}

func hasStreamLinkClass(addrs []netaddr.CustomAddr, class TransportLinkClass) bool {
	for _, addr := range addrs {
		link, err := ParseStreamLinkAddr(addr)
		if err == nil && link.Class == class {
			return true
		}
	}
	return false
}

func hasStreamLinkInterface(addrs []netaddr.CustomAddr, iface string) bool {
	for _, addr := range addrs {
		link, err := ParseStreamLinkAddr(addr)
		if err == nil && link.Interface == iface {
			return true
		}
	}
	return false
}

func streamLinkStrings(addrs []netaddr.CustomAddr) string {
	var b strings.Builder
	for _, addr := range addrs {
		link, err := ParseStreamLinkAddr(addr)
		if err != nil {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(link.Interface)
		b.WriteByte('/')
		b.WriteString(string(link.Class))
		b.WriteByte('=')
		b.WriteString(link.DialAddr)
	}
	return b.String()
}
