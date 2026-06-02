package dns

import (
	"errors"
	"net/netip"
	"slices"

	"github.com/tmc/go-iroh/internal/pkarr"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// IrohTxtName is the DNS record name under which iroh TXT records are published.
const IrohTxtName = "_iroh"

// UserDataMaxLength is the maximum byte length of [UserData]. A DNS TXT
// character-string holds at most 255 bytes; subtracting the "user-data=" prefix
// leaves 245 bytes.
const UserDataMaxLength = 245

// ErrUserDataTooLong is returned when a [UserData] value exceeds
// [UserDataMaxLength].
var ErrUserDataTooLong = errors.New("user data: max length exceeded")

// UserData is application-defined data published and resolved through endpoint
// discovery. It is a UTF-8 string of at most [UserDataMaxLength] bytes. iroh
// neither inspects nor uses it.
type UserData struct {
	s string
}

// NewUserData returns a UserData wrapping s, or [ErrUserDataTooLong] if s
// exceeds [UserDataMaxLength] bytes.
func NewUserData(s string) (UserData, error) {
	if len(s) > UserDataMaxLength {
		return UserData{}, ErrUserDataTooLong
	}
	return UserData{s: s}, nil
}

// String returns the user data string.
func (u UserData) String() string { return u.s }

// MarshalText implements encoding.TextMarshaler.
func (u UserData) MarshalText() ([]byte, error) {
	return []byte(u.s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *UserData) UnmarshalText(text []byte) error {
	parsed, err := NewUserData(string(text))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// EndpointData is the addressing and metadata published about an endpoint: a set
// of transport addresses (in priority order) and optional [UserData]. It does
// not include the endpoint's id; see [EndpointInfo].
//
// The zero value is an empty EndpointData and is ready to use.
type EndpointData struct {
	// addrs is the ordered, de-duplicated set of transport addresses. Order is
	// preserved (it encodes priority) while duplicates are removed.
	addrs    []netaddr.TransportAddr
	userData *UserData
}

// NewEndpointData returns an EndpointData with the given addresses. Order is
// preserved; duplicates are removed.
func NewEndpointData(addrs ...netaddr.TransportAddr) EndpointData {
	d := EndpointData{}
	d.AddAddrs(addrs...)
	return d
}

// AddRelayURL adds a relay URL to the end of the address list, unless already
// present.
func (d *EndpointData) AddRelayURL(u netaddr.RelayURL) {
	d.AddAddrs(netaddr.RelayAddr{URL: u})
}

// AddIPAddrs adds IP addresses in order, skipping duplicates and existing ones.
func (d *EndpointData) AddIPAddrs(addrs ...netip.AddrPort) {
	conv := make([]netaddr.TransportAddr, len(addrs))
	for i, a := range addrs {
		conv[i] = netaddr.IPAddr{Addr: a}
	}
	d.AddAddrs(conv...)
}

// AddAddrs adds addresses in order, skipping duplicates and ones already
// present. Duplicate filtering preserves the existing order.
func (d *EndpointData) AddAddrs(addrs ...netaddr.TransportAddr) {
	for _, a := range addrs {
		if !d.contains(a) {
			d.addrs = append(d.addrs, a)
		}
	}
}

// SetUserData sets or clears the user data.
func (d *EndpointData) SetUserData(u *UserData) { d.userData = u }

// ClearIPAddrs removes all direct IP addresses.
func (d *EndpointData) ClearIPAddrs() {
	d.addrs = slices.DeleteFunc(d.addrs, func(a netaddr.TransportAddr) bool {
		_, ok := a.(netaddr.IPAddr)
		return ok
	})
}

// ClearRelayURLs removes all relay addresses.
func (d *EndpointData) ClearRelayURLs() {
	d.addrs = slices.DeleteFunc(d.addrs, func(a netaddr.TransportAddr) bool {
		_, ok := a.(netaddr.RelayAddr)
		return ok
	})
}

// Addrs returns the ordered transport addresses.
func (d EndpointData) Addrs() []netaddr.TransportAddr { return slices.Clone(d.addrs) }

// RelayURLs returns the relay URLs in order.
func (d EndpointData) RelayURLs() []netaddr.RelayURL {
	var out []netaddr.RelayURL
	for _, a := range d.addrs {
		if r, ok := a.(netaddr.RelayAddr); ok {
			out = append(out, r.URL)
		}
	}
	return out
}

// IPAddrs returns the direct IP addresses in order.
func (d EndpointData) IPAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range d.addrs {
		if ip, ok := a.(netaddr.IPAddr); ok {
			out = append(out, ip.Addr)
		}
	}
	return out
}

// UserData returns the user data, or nil if unset.
func (d EndpointData) UserData() *UserData { return d.userData }

// HasAddrs reports whether any addresses are present.
func (d EndpointData) HasAddrs() bool { return len(d.addrs) > 0 }

func (d EndpointData) contains(a netaddr.TransportAddr) bool {
	return slices.ContainsFunc(d.addrs, func(x netaddr.TransportAddr) bool {
		return x.Compare(a) == 0
	})
}

// EndpointDataFromAddr builds EndpointData from an [netaddr.EndpointAddr], taking
// its (already de-duplicated, sorted) addresses.
func EndpointDataFromAddr(addr netaddr.EndpointAddr) EndpointData {
	return EndpointData{addrs: addr.Addrs()}
}

// EndpointInfo couples an [key.EndpointID] with the [EndpointData] published
// about it.
type EndpointInfo struct {
	// ID is the endpoint this information is about.
	ID key.EndpointID
	// Data is the addressing and metadata.
	Data EndpointData
}

// EndpointInfoFromAddr converts an [netaddr.EndpointAddr] into an EndpointInfo.
func EndpointInfoFromAddr(addr netaddr.EndpointAddr) EndpointInfo {
	return EndpointInfo{ID: addr.ID, Data: EndpointDataFromAddr(addr)}
}

// Addr converts the info into an [netaddr.EndpointAddr].
func (e EndpointInfo) Addr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(e.ID, e.Data.addrs...)
}

// ToTxtStrings renders the endpoint info as "key=value" TXT record strings.
func (e EndpointInfo) ToTxtStrings() []string {
	return e.toAttrs().toTxtStrings()
}

// ToPkarrSignedPacket builds a pkarr signed packet for this endpoint info,
// signed with secretKey and using the given record TTL in seconds.
func (e EndpointInfo) ToPkarrSignedPacket(secretKey key.SecretKey, ttl uint32) (*pkarr.SignedPacket, error) {
	return e.toAttrs().toPkarrSignedPacket(secretKey, ttl)
}

// EndpointInfoFromTxtLookup parses an EndpointInfo from DNS TXT lookup results.
// domainName is the queried name ("_iroh.<z32>.<origin>") and values are the
// TXT record string values.
func EndpointInfoFromTxtLookup(domainName string, values []string) (EndpointInfo, error) {
	attrs, err := txtAttrsFromTxtLookup(domainName, values)
	if err != nil {
		return EndpointInfo{}, err
	}
	return endpointInfoFromAttrs(attrs), nil
}

// EndpointInfoFromPkarrSignedPacket parses an EndpointInfo from a pkarr signed
// packet.
func EndpointInfoFromPkarrSignedPacket(packet *pkarr.SignedPacket) (EndpointInfo, error) {
	attrs, err := txtAttrsFromPkarrSignedPacket(packet)
	if err != nil {
		return EndpointInfo{}, err
	}
	return endpointInfoFromAttrs(attrs), nil
}
