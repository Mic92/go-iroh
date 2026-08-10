//go:build linux

package socket

import (
	"net"
	"syscall"
	"testing"
	"unsafe"

	"github.com/tmc/go-iroh/key"
	"golang.org/x/sys/unix"
)

func TestMagicConnWriteMsgUDPSplitsMappedDestination(t *testing.T) {
	secret, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	sock := NewSocket()
	m := NewMagicConnRelayOnly(sock, nil)
	t.Cleanup(func() { m.Close() })

	var got []string
	id := secret.Public().EndpointID()
	m.SetEndpointSender(func(remote key.EndpointID, p []byte) bool {
		if !remote.Equal(id) {
			t.Errorf("remote = %s, want %s", remote, id)
		}
		got = append(got, string(p))
		return true
	})
	addr := net.UDPAddrFromAddrPort(sock.EndpointIDMappedAddrFor(id).AddrPort())
	payload := []byte("abcdefg")
	n, _, err := m.WriteMsgUDP(payload, udpSegmentMessage(3), addr)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d bytes, want %d", n, len(payload))
	}
	want := []string{"abc", "def", "g"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("segment %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUDPSegmentSize(t *testing.T) {
	for _, test := range []struct {
		name string
		oob  []byte
		want int
	}{
		{name: "none"},
		{name: "segment", oob: udpSegmentMessage(1200), want: 1200},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := udpSegmentSize(test.oob); got != test.want {
				t.Fatalf("udpSegmentSize = %d, want %d", got, test.want)
			}
		})
	}
}

func udpSegmentMessage(size uint16) []byte {
	const dataLen = 2
	b := make([]byte, unix.CmsgSpace(dataLen))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	header.Level = syscall.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(dataLen))
	*(*uint16)(unsafe.Pointer(&b[unix.CmsgSpace(0)])) = size
	return b
}
