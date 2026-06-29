package docs

import (
	"fmt"

	"github.com/tmc/go-iroh/internal/postcard"
	"lukechampine.com/blake3"
)

// Fingerprint is a range-reconciliation fingerprint.
type Fingerprint [32]byte

// SyncConfig configures range reconciliation.
type SyncConfig struct {
	MaxSetSize  int
	SplitFactor int
	splitHook   func(Range)
}

// DefaultSyncConfig returns the Rust iroh-docs reconciliation defaults.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		MaxSetSize:  1,
		SplitFactor: 2,
	}
}

func (c SyncConfig) withDefaults() SyncConfig {
	if c.MaxSetSize == 0 {
		c.MaxSetSize = 1
	}
	if c.SplitFactor < 2 {
		c.SplitFactor = 2
	}
	return c
}

// EmptyFingerprint returns the fingerprint of the empty set.
func EmptyFingerprint() Fingerprint {
	return Fingerprint(blake3.Sum256(nil))
}

// Xor assigns f to the bytewise xor of f and other.
func (f *Fingerprint) Xor(other Fingerprint) {
	for i := range f {
		f[i] ^= other[i]
	}
}

// Range is a wraparound half-open range of record identifiers.
type Range struct {
	Start RecordIdentifier
	End   RecordIdentifier
}

// NewRange returns the range [start, end).
func NewRange(start, end RecordIdentifier) Range {
	return Range{Start: start, End: end}
}

// IsAll reports whether r denotes the whole set.
func (r Range) IsAll() bool {
	return r.Start.Compare(r.End) == 0
}

// Contains reports whether id is in r.
func (r Range) Contains(id RecordIdentifier) bool {
	c := r.Start.Compare(r.End)
	switch {
	case c == 0:
		return true
	case c < 0:
		return r.Start.Compare(id) <= 0 && id.Compare(r.End) < 0
	default:
		return r.Start.Compare(id) <= 0 || id.Compare(r.End) < 0
	}
}

// RangeFingerprint is the fingerprint for a range.
type RangeFingerprint struct {
	Range       Range
	Fingerprint Fingerprint
}

// RangeValue is one entry and its content status in a range item.
type RangeValue struct {
	Entry  SignedEntry
	Status ContentStatus
}

// RangeItem transfers entries inside a range.
type RangeItem struct {
	Range     Range
	Values    []RangeValue
	HaveLocal bool
}

// MessagePart is one range reconciliation message part.
type MessagePart struct {
	Kind             MessagePartKind
	RangeFingerprint RangeFingerprint
	RangeItem        RangeItem
}

// MessagePartKind identifies a message part variant.
type MessagePartKind uint64

const (
	// MessagePartRangeFingerprint carries a range fingerprint.
	MessagePartRangeFingerprint MessagePartKind = iota
	// MessagePartRangeItem carries entries in a range.
	MessagePartRangeItem
)

// EncodePostcard encodes p as Rust ranger::MessagePart<SignedEntry>.
func (p MessagePart) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(p.Kind))
	switch p.Kind {
	case MessagePartRangeFingerprint:
		return e.Encode(p.RangeFingerprint)
	case MessagePartRangeItem:
		return e.Encode(p.RangeItem)
	default:
		return fmt.Errorf("docs: unknown message part %d", p.Kind)
	}
}

// DecodePostcard decodes p as Rust ranger::MessagePart<SignedEntry>.
func (p *MessagePart) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	p.Kind = MessagePartKind(kind)
	switch p.Kind {
	case MessagePartRangeFingerprint:
		return d.Decode(&p.RangeFingerprint)
	case MessagePartRangeItem:
		return d.Decode(&p.RangeItem)
	default:
		return fmt.Errorf("docs: unknown message part %d", p.Kind)
	}
}

// Values returns p's entries, if p is a range item.
func (p MessagePart) Values() []RangeValue {
	if p.Kind != MessagePartRangeItem {
		return nil
	}
	return append([]RangeValue(nil), p.RangeItem.Values...)
}

// Message is a range reconciliation message.
type Message struct {
	Parts []MessagePart
}

// Values returns all entry values carried by m.
func (m Message) Values() []RangeValue {
	var out []RangeValue
	for _, part := range m.Parts {
		out = append(out, part.Values()...)
	}
	return out
}

// ValueCount returns the number of entry values carried by m.
func (m Message) ValueCount() int {
	n := 0
	for _, part := range m.Parts {
		if part.Kind == MessagePartRangeItem {
			n += len(part.RangeItem.Values)
		}
	}
	return n
}
