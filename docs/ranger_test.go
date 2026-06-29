package docs

import (
	"encoding/hex"
	"testing"

	"github.com/tmc/go-iroh/internal/postcard"
)

func TestRangeContains(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	a := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("a"))
	b := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("b"))
	c := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("c"))

	tests := []struct {
		name string
		r    Range
		id   RecordIdentifier
		want bool
	}{
		{name: "all", r: NewRange(a, a), id: c, want: true},
		{name: "normal inside start", r: NewRange(a, c), id: a, want: true},
		{name: "normal inside middle", r: NewRange(a, c), id: b, want: true},
		{name: "normal excludes end", r: NewRange(a, c), id: c, want: false},
		{name: "wrap high", r: NewRange(c, b), id: c, want: true},
		{name: "wrap low", r: NewRange(c, b), id: a, want: true},
		{name: "wrap excludes end", r: NewRange(c, b), id: b, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Contains(tt.id); got != tt.want {
				t.Fatalf("Contains = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMessagePostcardSnapshot(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "wire-format-test", EmptyRecord(1_700_000_000_000_000))
	store := NewMemoryStore()
	store.Put(entry)

	message := store.InitialMessage()
	got, err := postcard.Marshal(message)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wantHex := "01005055154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5776972652d666f726d61742d746573745055154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5776972652d666f726d61742d746573742d70753f09c0231692888772de0e777e971f4b046cf1b6b45b4d5a4aa647489e"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("message postcard = %x, want %s", got, wantHex)
	}

	var decoded Message
	if err := postcard.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(decoded.Parts) != 1 || decoded.Parts[0].Kind != MessagePartRangeFingerprint {
		t.Fatalf("decoded parts = %#v", decoded.Parts)
	}
	if decoded.Parts[0].RangeFingerprint.Fingerprint != message.Parts[0].RangeFingerprint.Fingerprint {
		t.Fatal("decoded fingerprint differs")
	}
}

func TestRangeItemMessageValues(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", EmptyRecord(1))
	id := entry.Entry.ID
	message := Message{Parts: []MessagePart{{
		Kind: MessagePartRangeItem,
		RangeItem: RangeItem{
			Range:     NewRange(id, id),
			Values:    []RangeValue{{Entry: entry, Status: ContentMissing}},
			HaveLocal: true,
		},
	}}}

	if got := message.ValueCount(); got != 1 {
		t.Fatalf("ValueCount = %d, want 1", got)
	}
	values := message.Values()
	if len(values) != 1 || !values[0].Entry.Equal(entry) || values[0].Status != ContentMissing {
		t.Fatalf("Values = %#v", values)
	}
}
