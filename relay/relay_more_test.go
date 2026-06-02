package relay

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/netaddr"
)

func TestConfigWithAuthToken(t *testing.T) {
	u, _ := netaddr.ParseRelayURL("https://a.example.com")
	c := NewConfig(u, nil)
	c2 := c.WithAuthToken("token123")
	if c2.AuthToken != "token123" {
		t.Errorf("c2.AuthToken = %q, want %q", c2.AuthToken, "token123")
	}
	if c.AuthToken != "" {
		t.Errorf("original c.AuthToken = %q, want empty (copy must not mutate receiver)", c.AuthToken)
	}
}

func TestConfigString(t *testing.T) {
	u, _ := netaddr.ParseRelayURL("https://a.example.com")
	c := NewConfig(u, nil)
	if c.String() != u.String() {
		t.Errorf("c.String() = %q, want %q", c.String(), u.String())
	}
}

func TestMapInsertZeroValue(t *testing.T) {
	u, _ := netaddr.ParseRelayURL("https://a.example.com")
	var m Map // zero Map, nil relays
	prev, ok := m.Insert(NewConfig(u, nil))
	if ok {
		t.Errorf("Insert into zero map reported prev present: %+v", prev)
	}
	if m.relays == nil {
		t.Error("Insert should lazily initialize relays map")
	}
	if m.Len() != 1 {
		t.Errorf("len = %d, want 1", m.Len())
	}
}

func TestMapConfigsSorted(t *testing.T) {
	ub, _ := netaddr.ParseRelayURL("https://b.example.com")
	ua, _ := netaddr.ParseRelayURL("https://a.example.com")
	m := MapFromURLs(ub, ua)
	configs := m.Configs()
	if len(configs) != 2 {
		t.Fatalf("len(configs) = %d, want 2", len(configs))
	}
	if configs[0].URL.String() >= configs[1].URL.String() {
		t.Errorf("configs not URL-sorted: %q, %q", configs[0].URL.String(), configs[1].URL.String())
	}
}

func TestMapClone(t *testing.T) {
	u1, _ := netaddr.ParseRelayURL("https://a.example.com")
	u2, _ := netaddr.ParseRelayURL("https://b.example.com")
	u3, _ := netaddr.ParseRelayURL("https://c.example.com")
	m1 := NewMap(NewConfig(u1, nil), NewConfig(u2, nil))
	m2 := m1.Clone()
	m2.Insert(NewConfig(u3, nil))
	if m1.Len() != 2 {
		t.Errorf("original map len = %d, want 2 (clone must be independent)", m1.Len())
	}
	if m2.Len() != 3 {
		t.Errorf("clone len = %d, want 3", m2.Len())
	}
}

func TestMapString(t *testing.T) {
	ub, _ := netaddr.ParseRelayURL("https://b.example.com")
	ua, _ := netaddr.ParseRelayURL("https://a.example.com")
	m := MapFromURLs(ub, ua)
	s := m.String()
	if !strings.HasPrefix(s, "RelayMap{") || !strings.HasSuffix(s, "}") {
		t.Errorf("String() = %q, want RelayMap{...}", s)
	}
	if !strings.Contains(s, "https://a.example.com/") {
		t.Errorf("String() = %q, missing a.example.com", s)
	}
	if !strings.Contains(s, "https://b.example.com/") {
		t.Errorf("String() = %q, missing b.example.com", s)
	}
	// URLs render in sorted order, so a precedes b.
	if strings.Index(s, "a.example.com") > strings.Index(s, "b.example.com") {
		t.Errorf("String() = %q, URLs not in sorted order", s)
	}
}

func TestModeCustomNilMap(t *testing.T) {
	m := ModeCustom(nil)
	rm := m.Map()
	if rm == nil {
		t.Fatal("Mode.Map() returned nil")
	}
	if !rm.IsEmpty() {
		t.Errorf("ModeCustom(nil).Map() not empty, len = %d", rm.Len())
	}
}

func TestMustURLPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("mustURL did not panic on invalid url")
		}
		if !strings.Contains(fmt.Sprint(r), "invalid default url") {
			t.Errorf("panic message = %q, want substring %q", fmt.Sprint(r), "invalid default url")
		}
	}()
	// url.Parse rejects this: "first path segment in URL cannot contain colon".
	mustURL("ht!tp://invalid[")
}
