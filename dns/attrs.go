package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tmc/go-iroh/internal/pkarr"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// Errors returned when parsing iroh DNS records.
var (
	// ErrUnexpectedFormat is returned for a TXT value not of the form key=value.
	ErrUnexpectedFormat = errors.New("expected format `key=value`")
	// ErrUnknownAttr is returned for an unrecognized attribute key.
	ErrUnknownAttr = errors.New("could not convert key to attr")
	// ErrNumLabels is returned when a DNS name has too few labels.
	ErrNumLabels = errors.New("expected at least 2 labels")
	// ErrNotIrohRecord is returned when the first label is not "_iroh".
	ErrNotIrohRecord = errors.New("not an iroh record, expected `_iroh`")
)

// irohAttr is an attribute key for iroh TXT records. Keys are kebab-case.
type irohAttr string

const (
	attrRelay    irohAttr = "relay"
	attrAddr     irohAttr = "addr"
	attrUserData irohAttr = "user-data"
)

func parseIrohAttr(s string) (irohAttr, bool) {
	switch irohAttr(s) {
	case attrRelay, attrAddr, attrUserData:
		return irohAttr(s), true
	default:
		return "", false
	}
}

// txtAttrs is the set of attributes parsed from "_iroh" TXT records: an endpoint
// id plus a map from attribute key to its ordered values.
type txtAttrs struct {
	endpointID key.EndpointID
	attrs      map[irohAttr][]string
}

// endpointIDFromTxtName parses an EndpointID from an iroh DNS name. The first
// label must be "_iroh" and the second the z-base-32 endpoint id; later labels
// are ignored.
func endpointIDFromTxtName(name string) (key.EndpointID, error) {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return key.EndpointID{}, fmt.Errorf("%w, received %d", ErrNumLabels, len(labels))
	}
	if labels[0] != IrohTxtName {
		return key.EndpointID{}, fmt.Errorf("%w, got %q", ErrNotIrohRecord, labels[0])
	}
	return key.PublicKeyFromZ32(labels[1])
}

// txtAttrsFromStrings builds txtAttrs from an endpoint id and "key=value"
// strings, preserving per-key value order.
func txtAttrsFromStrings(id key.EndpointID, values []string) (*txtAttrs, error) {
	attrs := map[irohAttr][]string{}
	for _, s := range values {
		key, value, ok := splitAttr(s)
		if !ok {
			return nil, fmt.Errorf("%w, received %q", ErrUnexpectedFormat, s)
		}
		attr, ok := parseIrohAttr(key)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownAttr, key)
		}
		attrs[attr] = append(attrs[attr], value)
	}
	return &txtAttrs{endpointID: id, attrs: attrs}, nil
}

func splitAttr(s string) (key, value string, ok bool) {
	parts := strings.SplitN(s, "=", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func txtAttrsFromTxtLookup(name string, values []string) (*txtAttrs, error) {
	id, err := endpointIDFromTxtName(name)
	if err != nil {
		return nil, err
	}
	return txtAttrsFromStrings(id, values)
}

func txtAttrsFromPkarrSignedPacket(packet *pkarr.SignedPacket) (*txtAttrs, error) {
	id := packet.PublicKey()
	return txtAttrsFromStrings(id, packet.TxtRecords(IrohTxtName))
}

// attrOrder is the key emission order. It matches the Rust BTreeMap<IrohAttr>
// iteration, which follows the derived Ord on the IrohAttr enum (declaration
// order: Relay, Addr, UserData) — not lexical key order.
var attrOrder = []irohAttr{attrRelay, attrAddr, attrUserData}

// toTxtStrings renders the attributes as "key=value" strings in the reference's
// BTreeMap order (relay, addr, user-data).
func (a *txtAttrs) toTxtStrings() []string {
	var out []string
	for _, k := range attrOrder {
		for _, v := range a.attrs[k] {
			out = append(out, string(k)+"="+v)
		}
	}
	return out
}

func (a *txtAttrs) toPkarrSignedPacket(secretKey key.SecretKey, ttl uint32) (*pkarr.SignedPacket, error) {
	return pkarr.FromTxtStrings(secretKey, IrohTxtName, a.toTxtStrings(), ttl)
}

// toAttrs converts an EndpointInfo into txtAttrs, preserving address order.
func (e EndpointInfo) toAttrs() *txtAttrs {
	attrs := map[irohAttr][]string{}
	for _, addr := range e.Data.addrs {
		switch v := addr.(type) {
		case netaddr.RelayAddr:
			attrs[attrRelay] = append(attrs[attrRelay], v.URL.String())
		case netaddr.IPAddr:
			attrs[attrAddr] = append(attrs[attrAddr], v.Addr.String())
		case netaddr.CustomAddr:
			attrs[attrAddr] = append(attrs[attrAddr], v.BareString())
		}
	}
	if e.Data.userData != nil {
		attrs[attrUserData] = append(attrs[attrUserData], e.Data.userData.String())
	}
	return &txtAttrs{endpointID: e.ID, attrs: attrs}
}

// endpointInfoFromAttrs converts parsed txtAttrs back into an EndpointInfo. It
// mirrors endpoint_info_from_attrs: relay URLs first, then addr values parsed as
// IP-then-custom, with unparseable values skipped; the first user-data wins.
func endpointInfoFromAttrs(attrs *txtAttrs) EndpointInfo {
	var addrs []netaddr.TransportAddr
	for _, s := range attrs.attrs[attrRelay] {
		if u, err := url.Parse(s); err == nil {
			addrs = append(addrs, netaddr.RelayAddr{URL: netaddr.RelayURLFromURL(u)})
		}
	}
	for _, s := range attrs.attrs[attrAddr] {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			addrs = append(addrs, netaddr.IPAddr{Addr: ap})
		} else if ca, err := netaddr.ParseCustomAddr(s); err == nil {
			addrs = append(addrs, ca)
		}
	}
	data := EndpointData{}
	if vs := attrs.attrs[attrUserData]; len(vs) > 0 {
		if u, err := NewUserData(vs[0]); err == nil {
			data.SetUserData(&u)
		}
	}
	data.AddAddrs(addrs...)
	return EndpointInfo{ID: attrs.endpointID, Data: data}
}
