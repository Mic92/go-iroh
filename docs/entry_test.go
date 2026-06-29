package docs

import (
	"encoding/hex"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/postcard"
)

func TestSignedEntryPostcardSnapshot(t *testing.T) {
	author := NewAuthor(repeat32(0xa1))
	namespace := NewNamespaceSecret(repeat32(0xb2))
	record := NewRecord(blobs.EmptyHash, 0, 1_700_000_000_000_000)
	id := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("wire-format-test"))
	signed := NewSignedEntry(NewEntry(id, record), namespace, author)

	got, err := postcard.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wantHex := "4b523f1b6d9b00a4779fc9f8f105a9e36f062ceb7d511b632905782042ad30acb6dd07bfced4ecd5f3aa58321e8ace63f48f988ed8461bfdcd8b0e902187a10e228ddc6998329b7faa64875fe80da36406ea8d87e3e57bb048323e9cb66c0b343b60c4e709fb978b878e37d0c362edfc06c8cdc774c8b29d94e48eaa06cca60f5055154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5776972652d666f726d61742d7465737400af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f32628080f9c0c1c48203"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("signed entry postcard = %x, want %s", got, wantHex)
	}
	var decoded SignedEntry
	if err := postcard.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !decoded.Equal(signed) {
		t.Fatalf("decoded signed entry differs")
	}
	if err := decoded.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAuthorPostcardSnapshot(t *testing.T) {
	author := NewAuthor(repeat32(0xa1))
	got, err := postcard.Marshal(author)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "20a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	if hex.EncodeToString(got) != want {
		t.Fatalf("author postcard = %x, want %s", got, want)
	}
	var decoded Author
	if err := postcard.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.String() != author.String() {
		t.Fatalf("decoded author = %s, want %s", decoded, author)
	}
}

func TestNamespaceSecretPostcardSnapshot(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	got, err := postcard.Marshal(namespace)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "20b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	if hex.EncodeToString(got) != want {
		t.Fatalf("namespace postcard = %x, want %s", got, want)
	}
	var decoded NamespaceSecret
	if err := postcard.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.String() != namespace.String() {
		t.Fatalf("decoded namespace = %s, want %s", decoded, namespace)
	}
}

func TestEntryValidateEmpty(t *testing.T) {
	author := NewAuthor(repeat32(0xa1))
	namespace := NewNamespaceSecret(repeat32(0xb2))
	id := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("k"))
	if err := NewEntry(id, EmptyRecord(1)).ValidateEmpty(); err != nil {
		t.Fatalf("empty record invalid: %v", err)
	}
	if err := NewEntry(id, NewRecord(blobs.NewHash([]byte("x")), 1, 1)).ValidateEmpty(); err != nil {
		t.Fatalf("content record invalid: %v", err)
	}
	if err := NewEntry(id, NewRecord(blobs.EmptyHash, 1, 1)).ValidateEmpty(); err == nil {
		t.Fatal("empty hash with nonzero length accepted")
	}
}

func repeat32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}
