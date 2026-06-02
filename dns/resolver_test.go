package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
)

// fakeLookuper returns canned TXT values for the expected name.
type fakeLookuper struct {
	wantName string
	values   []string
	t        *testing.T
}

func (f fakeLookuper) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name != f.wantName {
		f.t.Errorf("LookupTXT(%q), want %q", name, f.wantName)
	}
	return f.values, nil
}

func TestLookupEndpointByID(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	wantName := IrohTxtName + "." + id.Z32() + "." + N0DNSEndpointOriginProd
	r := &Resolver{Lookuper: fakeLookuper{
		wantName: wantName,
		values:   []string{"relay=https://r.example.com/", "addr=127.0.0.1:1234"},
		t:        t,
	}}
	info, err := r.LookupEndpointByID(context.Background(), id, N0DNSEndpointOriginProd)
	if err != nil {
		t.Fatalf("LookupEndpointByID: %v", err)
	}
	if !info.ID.Equal(id) {
		t.Errorf("id = %s, want %s", info.ID, id)
	}
	if got := info.Data.IPAddrs(); len(got) != 1 || got[0] != netip.MustParseAddrPort("127.0.0.1:1234") {
		t.Errorf("IPAddrs = %v", got)
	}
	if got := info.Data.RelayURLs(); len(got) != 1 {
		t.Errorf("RelayURLs = %v", got)
	}
}

func TestLookupEndpointByIDUsesZBase32Name(t *testing.T) {
	id := testID(t)
	const wantZ32 = "dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy"
	if got := id.Z32(); got != wantZ32 {
		t.Fatalf("Z32 = %q, want %q", got, wantZ32)
	}
	wantName := IrohTxtName + "." + wantZ32 + "." + N0DNSEndpointOriginProd
	r := &Resolver{Lookuper: fakeLookuper{
		wantName: wantName,
		values:   []string{"relay=https://r.example.com/"},
		t:        t,
	}}
	if _, err := r.LookupEndpointByID(context.Background(), id, N0DNSEndpointOriginProd); err != nil {
		t.Fatalf("LookupEndpointByID: %v", err)
	}
}
