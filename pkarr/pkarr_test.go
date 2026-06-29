package pkarr_test

import (
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/pkarr"
)

func TestRoundTrip(t *testing.T) {
	sk := key.NewSecretKey([32]byte{1})
	packet, err := pkarr.FromTxtStrings(sk, "_content", []string{"blake3:00"}, 30)
	if err != nil {
		t.Fatalf("FromTxtStrings: %v", err)
	}
	got, err := pkarr.FromBytes(packet.Bytes())
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	records := got.TxtRecords("_content")
	if len(records) != 1 || records[0] != "blake3:00" {
		t.Fatalf("TxtRecords = %q, want [blake3:00]", records)
	}
	payload := packet.RelayPayload()
	fromRelay, err := pkarr.FromRelayPayload(sk.Public(), payload)
	if err != nil {
		t.Fatalf("FromRelayPayload: %v", err)
	}
	if !fromRelay.PublicKey().Equal(sk.Public()) {
		t.Fatal("relay packet public key mismatch")
	}
}
