package quic

import "testing"

func TestRemoteAddrValidated(t *testing.T) {
	c := &Conn{}
	if c.RemoteAddrValidated() {
		t.Fatal("zero Conn RemoteAddrValidated = true, want false")
	}
	c.remoteAddrValidated = true
	if !c.RemoteAddrValidated() {
		t.Fatal("validated Conn RemoteAddrValidated = false, want true")
	}
}
