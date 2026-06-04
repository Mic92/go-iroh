package dns_test

import (
	"testing"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
)

func TestSignedPacketPublicAPI(t *testing.T) {
	sk, err := key.ParseSecretKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	want := dns.EndpointInfo{ID: sk.Public().EndpointID()}
	packet, err := want.ToSignedPacket(sk, 30)
	if err != nil {
		t.Fatalf("ToSignedPacket: %v", err)
	}

	var named *dns.SignedPacket = packet
	parsed, err := dns.SignedPacketFromBytes(named.Bytes())
	if err != nil {
		t.Fatalf("SignedPacketFromBytes: %v", err)
	}
	got, err := dns.EndpointInfoFromSignedPacket(parsed)
	if err != nil {
		t.Fatalf("EndpointInfoFromSignedPacket: %v", err)
	}
	if got.ID != want.ID {
		t.Fatalf("EndpointInfoFromSignedPacket ID = %v, want %v", got.ID, want.ID)
	}
}
