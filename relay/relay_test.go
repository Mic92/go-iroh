package relay

import (
	"testing"

	"github.com/tmc/go-iroh/netaddr"
)

func TestMapInsertGetRemove(t *testing.T) {
	u1, _ := netaddr.ParseRelayURL("https://a.example.com")
	u2, _ := netaddr.ParseRelayURL("https://b.example.com")
	m := NewMap()
	if !m.IsEmpty() {
		t.Fatal("new map should be empty")
	}
	m.Insert(NewConfig(u1, nil))
	m.Insert(Config{URL: u2, QUIC: &QUICConfig{Port: DefaultQUICPort}})
	if m.Len() != 2 {
		t.Fatalf("len = %d, want 2", m.Len())
	}
	if !m.Contains(u1) {
		t.Error("should contain u1")
	}
	c, ok := m.Get(u2)
	if !ok || c.QUIC == nil || c.QUIC.Port != DefaultQUICPort {
		t.Errorf("get u2 = %+v, %v", c, ok)
	}
	if _, ok := m.Remove(u1); !ok {
		t.Error("remove u1 should report present")
	}
	if m.Len() != 1 {
		t.Errorf("len after remove = %d, want 1", m.Len())
	}
}

func TestMapURLsSorted(t *testing.T) {
	ub, _ := netaddr.ParseRelayURL("https://b.example.com")
	ua, _ := netaddr.ParseRelayURL("https://a.example.com")
	m := MapFromURLs(ub, ua)
	urls := m.URLs()
	if len(urls) != 2 || urls[0].String() != "https://a.example.com/" {
		t.Errorf("URLs not sorted: %v", []string{urls[0].String(), urls[1].String()})
	}
}

func TestModeMaps(t *testing.T) {
	if !ModeDisabled().Map().IsEmpty() {
		t.Error("disabled mode map should be empty")
	}
	if ModeDefault().Map().Len() != 4 {
		t.Errorf("default map should have 4 relays, got %d", ModeDefault().Map().Len())
	}
	if ModeStaging().Map().Len() != 1 {
		t.Errorf("staging map should have 1 relay, got %d", ModeStaging().Map().Len())
	}
	u, _ := netaddr.ParseRelayURL("https://custom.example.com")
	if ModeCustomURLs(u).Map().Len() != 1 {
		t.Error("custom mode map mismatch")
	}
}

func TestDefaultMapHasN0Relays(t *testing.T) {
	urls := DefaultMap().URLs()
	found := false
	for _, u := range urls {
		// The FQDN trailing dot is preserved in the relay URL host.
		if u.Host() == "use1-1.relay.n0.iroh-canary.iroh.link." {
			found = true
		}
	}
	if !found {
		t.Errorf("default map missing NA-east relay; got %v", urls)
	}
}

func TestMapFromURLsNoQUICForPlainHTTP(t *testing.T) {
	https, _ := netaddr.ParseRelayURL("https://relay.example")
	plain, _ := netaddr.ParseRelayURL("http://10.0.0.1:3340")
	m := MapFromURLs(https, plain)
	if c, _ := m.Get(https); c.QUIC == nil {
		t.Fatalf("https relay lost its QUIC config")
	}
	if c, _ := m.Get(plain); c.QUIC != nil {
		t.Fatalf("http relay got QUIC config %+v; QAD needs TLS", c.QUIC)
	}
}
